package thrift

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"testing"
)

// legyTestSession returns a session with fixed key material for frame tests.
func legyTestSession(t *testing.T) *LEGYSession {
	t.Helper()
	s := &LEGYSession{MaxSerialGap: LEGYDefaultMaxSerialGap}
	for i := 0; i < 16; i++ {
		s.EncryptKey[i] = byte(0x10 + i)
		s.DecryptKey[i] = byte(0x10 + i)
		s.HMACKey[i] = byte(i)
		s.BaseIV[i] = byte(i)
	}
	return s
}

// --- hardcoded public keys -------------------------------------------------

func TestLEGYHardcodedPubKeys(t *testing.T) {
	if hex := "04cce101191a5f7b9cc01905602a74faef51f09919980a2669831c1a1b0805888aac06ce1bd376eb4f11227cb59056047b88c40f47666d369160f7c98adfd46ff4"; hex != mustHex(LEGYServerPubKey[:]) {
		t.Fatalf("LEGYServerPubKey = %s, want %s", mustHex(LEGYServerPubKey[:]), hex)
	}
	if hex := "04f2f529c32550402b08a085f69074cdead32e4b32a1f654f8124f1092d72f04096912e65665d52ece726c86b7d09e83f512aee4083730a4f495c7895fcd57442d"; hex != mustHex(LEGYXFSPeerPubKey[:]) {
		t.Fatalf("LEGYXFSPeerPubKey = %s, want %s", mustHex(LEGYXFSPeerPubKey[:]), hex)
	}
	for name, k := range map[string][65]byte{"server": LEGYServerPubKey, "xfs": LEGYXFSPeerPubKey} {
		if k[0] != 0x04 {
			t.Fatalf("%s key prefix = %#x, want 0x04", name, k[0])
		}
		x := new(big.Int).SetBytes(k[1:33])
		y := new(big.Int).SetBytes(k[33:65])
		// NID 714 == secp256k1 in OpenSSL/BoringSSL; both keys must be valid
		// secp256k1 points (verified against liblegy.so .rodata 0xf273/0xf130).
		if !legyCurve.IsOnCurve(x, y) {
			t.Fatalf("%s key not on secp256k1", name)
		}
		if _, err := legyPubFromUncompressed(k[:]); err != nil {
			t.Fatalf("%s key parse: %v", name, err)
		}
	}
}

func mustHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = digits[c>>4]
		out[i*2+1] = digits[c&0xf]
	}
	return string(out)
}

// --- serial packing (base64 6-bit packing of 16 bits into 3 chars) ---------

func TestLEGYSboxRoundtrip(t *testing.T) {
	for s := uint32(0); s <= 0xffff; s++ {
		w := EncodeSerialBytes(uint16(s))
		if got := DecodeSerialBytes(w); got != uint16(s) {
			t.Fatalf("roundtrip serial %#x: got %#x", s, got)
		}
		w2 := EncodeSerial(uint16(s))
		if got := DecodeSerial(w2[0], w2[1], w2[2]); got != uint16(s) {
			t.Fatalf("wrapper roundtrip serial %#x: got %#x", s, got)
		}
	}
}

func TestLEGYSboxNativeVectors(t *testing.T) {
	// lec_get_serialno @0x182c8 formula with the decode table at 0xf173.
	cases := []struct {
		b0, b1, b2 byte
		want       uint16
	}{
		{'A', 'A', 'A', 0x0000},
		{'L', 'E', 'C', 0x402c},
		{'z', '9', '/', 0xdfcf},
	}
	for _, c := range cases {
		if got := DecodeSerialBytes([3]byte{c.b0, c.b1, c.b2}); got != c.want {
			t.Fatalf("DecodeSerialBytes(%q,%q,%q) = %#04x, want %#04x", c.b0, c.b1, c.b2, got, c.want)
		}
	}
	enc := []struct {
		serial uint16
		want   [3]byte
	}{
		{0x402c, [3]byte{'L', 'E', 'A'}},
		{0xbeef, [3]byte{'7', '7', '4'}},
		{0x0001, [3]byte{'A', 'Q', 'A'}},
		{0xffff, [3]byte{'/', '/', '8'}},
	}
	for _, c := range enc {
		if got := EncodeSerialBytes(c.serial); got != c.want {
			t.Fatalf("EncodeSerialBytes(%#04x) = %q, want %q", c.serial, got, c.want)
		}
	}
}

// --- frame encode/decode (base64(serial_LE16 || ct || tag16)) --------------

func TestLEGYFrameEncodeDecodeGolden(t *testing.T) {
	// base64_raw(2c 40 || 16x00) — 18 bytes -> 24 chars.
	if got := string(EncodeFrame(0x402c, make([]byte, LEGYGCMTAGSize))); got != "LEAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("EncodeFrame(0x402c, 16x00) = %q", got)
	}
	if got := string(EncodeFrame(1, make([]byte, LEGYGCMTAGSize))); got != "AQAAAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("EncodeFrame(1, 16x00) = %q", got)
	}
	serial, ctTag, err := DecodeFrame([]byte("LEAAAAAAAAAAAAAAAAAAAAAA"))
	if err != nil {
		t.Fatalf("DecodeFrame: %v", err)
	}
	if serial != 0x402c || len(ctTag) != LEGYGCMTAGSize || !bytes.Equal(ctTag, make([]byte, LEGYGCMTAGSize)) {
		t.Fatalf("DecodeFrame = serial %#x ctTag %x", serial, ctTag)
	}
	// serial via lec_get_serialno packing of the first 3 wire chars
	if s, err := LEGYGetSerialNo([]byte("LEAAAAAAAAAAAAAAAAAAAAAA")); err != nil || s != 0x402c {
		t.Fatalf("LEGYGetSerialNo = %d, %v; want 0x402c", s, err)
	}
	if _, err := LEGYGetSerialNo([]byte{'L', 'E'}); err != ErrLEGYShortFrame {
		t.Fatalf("want ErrLEGYShortFrame, got %v", err)
	}
	// roundtrip
	wire := EncodeFrame(0xbeef, []byte("ciphertext+tag-body"))
	serial, ctTag, err = DecodeFrame(wire)
	if err != nil || serial != 0xbeef || string(ctTag) != "ciphertext+tag-body" {
		t.Fatalf("roundtrip: serial=%#x ctTag=%q err=%v", serial, ctTag, err)
	}
	// padded input is accepted too
	padded := base64.StdEncoding.EncodeToString(append([]byte{0x2c, 0x40}, make([]byte, 16)...))
	if serial, _, err := DecodeFrame([]byte(padded)); err != nil || serial != 0x402c {
		t.Fatalf("padded decode: serial=%#x err=%v", serial, err)
	}
	// garbage rejected
	if _, _, err := DecodeFrame([]byte("!!!not-base64!!!")); err == nil {
		t.Fatalf("expected error for invalid base64")
	}
	if _, _, err := DecodeFrame([]byte("AAAA")); !errors.Is(err, ErrLEGYShortFrame) {
		t.Fatalf("want ErrLEGYShortFrame, got %v", err)
	}
}

// --- nonce vectors: (FILL*10 || BE16(serial)) XOR baseIV[0:12] -------------

func TestLEGYNonceVectors(t *testing.T) {
	var baseIV [16]byte
	for i := range baseIV {
		baseIV[i] = byte(i * 0x11) // 00 11 22 ... ff
	}
	cases := []struct {
		serial uint16
		fill   byte
		want   string // hex
	}{
		{0x402c, LEGYFillClientToServer, "00112233445566778899ea97"},
		{0x402c, LEGYFillServerToClient, "ffeeddccbbaa99887766ea97"},
		{0x0001, LEGYFillClientToServer, "00112233445566778899aaba"},
		{0x0001, LEGYFillServerToClient, "ffeeddccbbaa99887766aaba"},
	}
	for _, c := range cases {
		got := LEGYComputeNonce(c.serial, baseIV, c.fill)
		if mustHex(got[:]) != c.want {
			t.Fatalf("LEGYComputeNonce(%#x, fill=%#x) = %s, want %s", c.serial, c.fill, mustHex(got[:]), c.want)
		}
	}
}

// --- encrypt/decrypt roundtrip, both directions -----------------------------

func TestLEGYEncryptDecryptRoundtrip(t *testing.T) {
	s := legyTestSession(t)
	plaintext := []byte{0x80, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}

	// client->server frame (FILL=0x00), verified by the server side.
	frame, err := s.EncryptLEGYFrame(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// wire is base64 text: 2 + len(pt) + 16 decoded bytes
	raw, err := base64.RawStdEncoding.DecodeString(string(frame))
	if err != nil {
		t.Fatalf("frame not base64: %v", err)
	}
	if want := 2 + len(plaintext) + LEGYGCMTAGSize; len(raw) != want {
		t.Fatalf("decoded frame len = %d, want %d", len(raw), want)
	}
	if binary.LittleEndian.Uint16(raw[0:2]) != 1 {
		t.Fatalf("serial in frame = %d, want 1", binary.LittleEndian.Uint16(raw[0:2]))
	}
	if ser, _ := LEGYGetSerialNo(frame); ser != 1 {
		t.Fatalf("LEGYGetSerialNo = %d, want 1", ser)
	}
	dec, err := s.DecryptLEGYFrameServer(frame)
	if err != nil {
		t.Fatalf("server decrypt: %v", err)
	}
	if !bytes.Equal(dec, plaintext) {
		t.Fatalf("mismatch: %x vs %x", dec, plaintext)
	}

	// server->client frame (FILL=0xFF), verified by the client side.
	sframe, err := s.EncryptLEGYFrameServer([]byte("pong"))
	if err != nil {
		t.Fatalf("encrypt server: %v", err)
	}
	dec, err = s.DecryptLEGYFrame(sframe)
	if err != nil {
		t.Fatalf("client decrypt: %v", err)
	}
	if string(dec) != "pong" {
		t.Fatalf("mismatch: %q", dec)
	}

	// direction matters: a client frame must NOT decrypt as a server frame
	if _, err := s.DecryptLEGYFrame(frame); err == nil {
		t.Fatalf("client frame decrypted with server FILL — nonce direction not enforced")
	}
	if _, err := s.DecryptLEGYFrameServer(sframe); err == nil {
		t.Fatalf("server frame decrypted with client FILL — nonce direction not enforced")
	}
	// tampering fails GCM
	bad := append([]byte(nil), frame...)
	bad[len(bad)-1] ^= 1
	if _, err := s.DecryptLEGYFrameServer(bad); err == nil {
		t.Fatalf("tampered frame decrypted")
	}
}

func TestLEGYAntiReplay(t *testing.T) {
	s := legyTestSession(t)
	s.MaxSerialGap = 3
	msg := []byte("replay test")
	frames := make([][]byte, 0, 6)
	for i := 0; i < 6; i++ {
		f, err := s.EncryptLEGYFrame(msg)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		frames = append(frames, f)
		if _, err := s.DecryptLEGYFrameServer(f); err != nil {
			t.Fatalf("decrypt %d: %v", i, err)
		}
	}
	// serial 1 is now outside the window (max=6, gap=3)
	if _, err := s.DecryptLEGYFrameServer(frames[0]); !errors.Is(err, ErrLEGYReplayDetected) {
		t.Fatalf("want ErrLEGYReplayDetected, got %v", err)
	}
}

// --- HKDF "legy fs key" vectors (KDF helper @0x18af8) ----------------------

func TestLEGYHKDFVectors(t *testing.T) {
	rands := make([]byte, 32) // clientRand16 || serverRand16
	for i := range rands {
		rands[i] = byte(i) // 00..1f
	}
	shared := make([]byte, 32)
	for i := range shared {
		shared[i] = byte(0x20 + i) // 20..3f
	}
	// Independent reference: PRK = HMAC-SHA256(key=rands, msg=shared);
	// OKM = HMAC-SHA256(PRK, "legy fs key" || 0x01).
	prk := hmac.New(sha256.New, rands)
	prk.Write(shared)
	okm := hmac.New(sha256.New, prk.Sum(nil))
	okm.Write([]byte(LEGYFSKeyLabel))
	okm.Write([]byte{0x01})
	wantOKM := okm.Sum(nil)
	if got := mustHex(wantOKM); got != "1188a75bad847b959e6ef9345766542d4ace2988972008f1848d4b6c3f005248" {
		t.Fatalf("reference OKM = %s", got)
	}

	s := NewLEGYSession(shared, rands)
	if got := mustHex(s.EncryptKey[:16]); got != "4ace2988972008f1848d4b6c3f005248" {
		t.Fatalf("EncryptKey[:16] = %s, want OKM[16:32]", got)
	}
	if got := mustHex(s.DecryptKey[:16]); got != "4ace2988972008f1848d4b6c3f005248" {
		t.Fatalf("DecryptKey[:16] = %s", got)
	}
	if got := mustHex(s.BaseIV[:]); got != "1188a75bad847b959e6ef9345766542d" {
		t.Fatalf("BaseIV = %s, want OKM[0:16]", got)
	}
}

// --- xxh32 + legy_hmac @0x174ec vectors -------------------------------------

func TestLEGYXXH32Vectors(t *testing.T) {
	cases := []struct {
		in   string
		want uint32
	}{
		{"", 0x02cc5d05},
		{"a", 0x550d7456},
		{"abc", 0x32d153ff},
		{"abcd", 0xa3643705},
		{"The quick brown fox jumps over the lazy dog", 0xe85ea4de},
	}
	for _, c := range cases {
		if got := xxh32([]byte(c.in)); got != c.want {
			t.Fatalf("xxh32(%q) = %#x, want %#x", c.in, got, c.want)
		}
	}
}

func TestLEGYHMACVectors(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	cases := []struct {
		key, data []byte
		want      string
	}{
		{key, []byte("hello"), "fe3900e6"},
		{key, []byte(""), "e41d64e1"},
		{key, []byte("LINE"), "c52ad77d"},
		{bytes.Repeat([]byte{0xaa}, 16), []byte("LINE"), "079e6077"},
	}
	for i, c := range cases {
		got := LEGYHMAC(c.key, c.data)
		if len(got) != LEGYHMACSize {
			t.Fatalf("case %d: mac len = %d, want %d", i, len(got), LEGYHMACSize)
		}
		if mustHex(got) != c.want {
			t.Fatalf("case %d: LEGYHMAC = %s, want %s", i, mustHex(got), c.want)
		}
	}
	// determinism + sensitivity
	if !bytes.Equal(LEGYHMAC(key, []byte("hello")), LEGYHMAC(key, []byte("hello"))) {
		t.Fatalf("MAC not deterministic")
	}
	if bytes.Equal(LEGYHMAC(key, []byte("hello")), LEGYHMAC(key, []byte("hellp"))) {
		t.Fatalf("MAC not data-sensitive")
	}
	if got := LEGYHMACSHA256(key, []byte("hello")); len(got) != 32 {
		t.Fatalf("LEGYHMACSHA256 len = %d, want 32", len(got))
	}
}

// --- ECDSA signature verification -------------------------------------------

func TestLEGYVerifyServerSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(legyCurve, rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	pub := elliptic.Marshal(legyCurve, key.X, key.Y) // 65-byte uncompressed
	msg := []byte("legy server auth")
	digest := sha256.Sum256(msg) // native ECDSA_do_verify takes the 32-byte digest
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !VerifyLEGYServerSignature(pub, msg, sig) {
		t.Fatalf("positive DER verify failed")
	}
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign raw: %v", err)
	}
	rb, sb := make([]byte, 32), make([]byte, 32)
	copy(rb[32-len(r.Bytes()):], r.Bytes())
	copy(sb[32-len(s.Bytes()):], s.Bytes())
	if !VerifyLEGYServerSignatureRaw(pub, msg, rb, sb) {
		t.Fatalf("positive raw verify failed")
	}
	// negatives
	if VerifyLEGYServerSignature(pub, []byte("other"), sig) {
		t.Fatalf("negative verify (msg) passed")
	}
	bad := append([]byte(nil), sig...)
	bad[len(bad)-1] ^= 0xff
	if VerifyLEGYServerSignature(pub, msg, bad) {
		t.Fatalf("negative verify (sig) passed")
	}
	key2, _ := ecdsa.GenerateKey(legyCurve, rand.Reader)
	pub2 := elliptic.Marshal(legyCurve, key2.X, key2.Y)
	if VerifyLEGYServerSignature(pub2, msg, sig) {
		t.Fatalf("negative verify (key) passed")
	}
	if VerifyLEGYServerSignature([]byte{0x04, 1, 2}, msg, sig) {
		t.Fatalf("negative verify (malformed pub) passed")
	}
	if VerifyLEGYServerSignatureRaw(pub, msg, rb, sb[:31]) {
		t.Fatalf("negative verify (short s) passed")
	}
	// the hardcoded server key must NOT verify a signature from an unrelated key
	if VerifyLEGYServerSignature(LEGYServerPubKey[:], msg, sig) {
		t.Fatalf("signature by random key verified against LEGYServerPubKey")
	}
	if VerifyLEGYServerSignatureRaw(LEGYServerPubKey[:], msg, rb, sb) {
		t.Fatalf("raw signature by random key verified against LEGYServerPubKey")
	}
}

// --- handshake message layer -------------------------------------------------

// legySimulateServer builds a 154-char server reply for the pending client
// hello in s, signed by serverKey (mirrors lec_handshake_server @0x17f94).
func legySimulateServer(t *testing.T, s *LEGYSession, serial uint16, serverKey *ecdsa.PrivateKey, serverRand [16]byte) string {
	t.Helper()
	serverPubComp := elliptic.MarshalCompressed(legyCurve, serverKey.X, serverKey.Y)
	msg := make([]byte, 0, 33+16+33+16)
	msg = append(msg, s.hsPubComp[:]...)
	msg = append(msg, s.hsRand[:]...)
	msg = append(msg, serverPubComp...)
	msg = append(msg, serverRand[:]...)
	digest := sha256.Sum256(msg)
	r, sigS, err := ecdsa.Sign(rand.Reader, serverKey, digest[:])
	if err != nil {
		t.Fatalf("server sign: %v", err)
	}
	rb, sb := make([]byte, 32), make([]byte, 32)
	copy(rb[32-len(r.Bytes()):], r.Bytes())
	copy(sb[32-len(sigS.Bytes()):], sigS.Bytes())

	reply := make([]byte, LEGYServerHelloLen)
	binary.LittleEndian.PutUint16(reply[0:2], serial)
	copy(reply[2:35], serverPubComp)
	copy(reply[35:51], serverRand[:])
	copy(reply[51:83], rb)
	copy(reply[83:115], sb)
	wire := legyB64Encode(reply)
	if len(wire) != LEGYServerHelloWireLen {
		t.Fatalf("server reply wire len = %d, want %d", len(wire), LEGYServerHelloWireLen)
	}
	return string(wire)
}

func TestLEGYHandshakeMessages(t *testing.T) {
	s := &LEGYSession{MaxSerialGap: LEGYDefaultMaxSerialGap}
	helloWire, err := LEGYClientHello(s, 0x1234)
	if err != nil {
		t.Fatalf("LEGYClientHello: %v", err)
	}
	// 53 raw bytes -> 71 unpadded base64 chars
	if len(helloWire) != LEGYClientHelloWireLen {
		t.Fatalf("hello wire len = %d, want %d", len(helloWire), LEGYClientHelloWireLen)
	}
	raw, err := base64.RawStdEncoding.DecodeString(helloWire)
	if err != nil || len(raw) != LEGYClientHelloLen {
		t.Fatalf("hello decode: len=%d err=%v", len(raw), err)
	}
	if serial := binary.LittleEndian.Uint16(raw[0:2]); serial != 0x1234 {
		t.Fatalf("hello serial = %#x, want 0x1234", serial)
	}
	if raw[2] != 0x00 || raw[3] != 0x01 {
		t.Fatalf("hello prefix = %x %x, want 00 01", raw[2], raw[3])
	}
	if _, err := legyPubFromCompressed(raw[4:37]); err != nil {
		t.Fatalf("hello pubComp: %v", err)
	}
	// first 3 wire chars carry the serial via the 6-bit packing
	if ser, _ := LEGYGetSerialNo([]byte(helloWire)); ser != 0x1234 {
		t.Fatalf("LEGYGetSerialNo(hello) = %#x, want 0x1234", ser)
	}

	// simulated server reply
	serverKey, err := ecdsa.GenerateKey(legyCurve, rand.Reader)
	if err != nil {
		t.Fatalf("server keygen: %v", err)
	}
	var serverRand [16]byte
	for i := range serverRand {
		serverRand[i] = byte(0xa0 + i)
	}
	replyWire := legySimulateServer(t, s, 0x1234, serverKey, serverRand)
	if len(replyWire) != LEGYServerHelloWireLen {
		t.Fatalf("reply wire len = %d, want %d", len(replyWire), LEGYServerHelloWireLen)
	}
	sh, err := LEGYParseServerHello(replyWire)
	if err != nil {
		t.Fatalf("LEGYParseServerHello: %v", err)
	}
	if sh.Serial != 0x1234 || sh.Rand != serverRand {
		t.Fatalf("parsed hello serial/rand mismatch: %#x %x", sh.Serial, sh.Rand)
	}
	if !bytes.Equal(sh.PubComp[:], elliptic.MarshalCompressed(legyCurve, serverKey.X, serverKey.Y)) {
		t.Fatalf("parsed hello pub mismatch")
	}

	// finish with the simulated server's key (injectable verify key)
	serverPub65 := elliptic.Marshal(legyCurve, serverKey.X, serverKey.Y)
	if err := legyHandshakeClientFinish(s, replyWire, serverPub65); err != nil {
		t.Fatalf("handshake finish: %v", err)
	}
	// independently derive the expected session keys
	clientPub, err := legyPubFromCompressed(s.hsPubComp[:])
	if err != nil {
		t.Fatalf("client pub: %v", err)
	}
	shared, err := legyECDH(serverKey, clientPub)
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	rands := append(append([]byte{}, s.hsRand[:]...), serverRand[:]...)
	prk := hmac.New(sha256.New, rands)
	prk.Write(shared)
	okmMAC := hmac.New(sha256.New, prk.Sum(nil))
	okmMAC.Write([]byte(LEGYFSKeyLabel))
	okmMAC.Write([]byte{0x01})
	okm := okmMAC.Sum(nil)
	if !bytes.Equal(s.EncryptKey[:16], okm[16:32]) {
		t.Fatalf("EncryptKey = %x, want OKM[16:32] = %x", s.EncryptKey[:16], okm[16:32])
	}
	if !bytes.Equal(s.BaseIV[:], okm[:16]) {
		t.Fatalf("BaseIV = %x, want OKM[0:16] = %x", s.BaseIV[:], okm[:16])
	}

	// full-duplex frame exchange with the derived session keys
	req, err := s.EncryptLEGYFrame([]byte("thrift request"))
	if err != nil {
		t.Fatalf("encrypt req: %v", err)
	}
	got, err := s.DecryptLEGYFrameServer(req)
	if err != nil || string(got) != "thrift request" {
		t.Fatalf("server decrypt req: %q, %v", got, err)
	}
	resp, err := s.EncryptLEGYFrameServer([]byte("thrift response"))
	if err != nil {
		t.Fatalf("encrypt resp: %v", err)
	}
	got, err = s.DecryptLEGYFrame(resp)
	if err != nil || string(got) != "thrift response" {
		t.Fatalf("client decrypt resp: %q, %v", got, err)
	}
}

func TestLEGYHandshakeNegative(t *testing.T) {
	serverKey, _ := ecdsa.GenerateKey(legyCurve, rand.Reader)
	serverPub65 := elliptic.Marshal(legyCurve, serverKey.X, serverKey.Y)
	var serverRand [16]byte

	// tampered signature must fail
	s := &LEGYSession{MaxSerialGap: LEGYDefaultMaxSerialGap}
	helloWire, err := LEGYClientHello(s, 1)
	if err != nil {
		t.Fatalf("hello: %v", err)
	}
	replyWire := legySimulateServer(t, s, 1, serverKey, serverRand)
	raw, _ := base64.RawStdEncoding.DecodeString(replyWire)
	raw[100] ^= 0xff // flip a bit inside s
	badWire := string(legyB64Encode(raw))
	if err := legyHandshakeClientFinish(s, badWire, serverPub65); !errors.Is(err, ErrLEGYBadSignature) {
		t.Fatalf("want ErrLEGYBadSignature, got %v", err)
	}

	// a valid reply signed by an unrelated key must fail against the real
	// hardcoded LEGYServerPubKey
	s2 := &LEGYSession{MaxSerialGap: LEGYDefaultMaxSerialGap}
	if _, err := LEGYClientHello(s2, 1); err != nil {
		t.Fatalf("hello2: %v", err)
	}
	reply2 := legySimulateServer(t, s2, 1, serverKey, serverRand)
	if err := LEGYHandshakeClientFinish(s2, reply2); !errors.Is(err, ErrLEGYBadSignature) {
		t.Fatalf("exported finish vs LEGYServerPubKey: want ErrLEGYBadSignature, got %v", err)
	}

	// finish without a pending hello
	s3 := &LEGYSession{}
	if err := LEGYHandshakeClientFinish(s3, replyWire); !errors.Is(err, ErrLEGYHandshake) {
		t.Fatalf("want ErrLEGYHandshake, got %v", err)
	}
	// malformed reply
	if _, err := LEGYParseServerHello("AAAA"); err == nil {
		t.Fatalf("want error for short reply")
	}
	_ = helloWire
}

// --- transport ---------------------------------------------------------------

type legyFakeTransport struct {
	req  bytes.Buffer
	resp []byte
	pos  int
}

func (f *legyFakeTransport) Open() error  { return nil }
func (f *legyFakeTransport) IsOpen() bool { return true }
func (f *legyFakeTransport) Close() error { return nil }
func (f *legyFakeTransport) Read(p []byte) (int, error) {
	if f.pos >= len(f.resp) {
		return 0, io.EOF
	}
	n := copy(p, f.resp[f.pos:])
	f.pos += n
	return n, nil
}
func (f *legyFakeTransport) Write(p []byte) (int, error) { return f.req.Write(p) }
func (f *legyFakeTransport) Flush(ctx context.Context) error {
	return nil
}
func (f *legyFakeTransport) RemainingBytes() uint64 { return 0 }

func TestLEGYTransport(t *testing.T) {
	s := legyTestSession(t)
	// server response frame (FILL=0xFF) for "pong"
	respFrame, err := s.EncryptLEGYFrameServer([]byte("pong"))
	if err != nil {
		t.Fatalf("encrypt resp: %v", err)
	}
	fake := &legyFakeTransport{resp: respFrame}
	lt := NewLEGYTransport(fake, s)

	msg := []byte("hello legy transport")
	if _, err := lt.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := lt.Flush(context.Background()); err != nil {
		t.Fatalf("flush: %v", err)
	}
	// the request on the wire must be one base64 client frame (FILL=0x00)
	wireReq := fake.req.Bytes()
	if _, _, err := DecodeFrame(wireReq); err != nil {
		t.Fatalf("request frame not decodable base64: %v", err)
	}
	// SendSerial was already 1 from the response frame, so the request is serial 2
	if ser, _ := LEGYGetSerialNo(wireReq); ser != uint32(s.SendSerial) {
		t.Fatalf("request serial = %d, want %d", ser, s.SendSerial)
	}
	reqPlain, err := s.DecryptLEGYFrameServer(wireReq)
	if err != nil || !bytes.Equal(reqPlain, msg) {
		t.Fatalf("server-side decrypt of request: %q, %v", reqPlain, err)
	}
	// client reads the decrypted response
	out, err := io.ReadAll(lt)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(out) != "pong" {
		t.Fatalf("response = %q, want %q", out, "pong")
	}
}

func TestLEGYContextFlush(t *testing.T) {
	var _ ContextFlusher = (*LEGYTransport)(nil)
	var _ TTransport = (*LEGYTransport)(nil)
}
