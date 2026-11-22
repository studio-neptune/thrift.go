/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package thrift

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/bits"

	"golang.org/x/crypto/hkdf"
)

// LEGY / LEC wire format, reverse-engineered from LINE APK v12.21.1
// lib/arm64-v8a/liblegy.so (ground truth: /tmp/legy.asm; spec: /tmp/LEC_SPEC.md).
//
// Data frame (lec_aes_encrypt @0x186e4 / lec_get_serialno @0x182c8):
//
//	wire frame = base64_raw( serial_LE16 || AES-128-GCM ciphertext || GCM tag[16] )
//
// The whole frame on the wire is unpadded base64 text (alphabet at .rodata
// 0xe014, encoder @0x17b50 emits no '=' padding). The 16-bit little-endian
// serial is the first two *decoded* bytes; equivalently the first 3 wire
// chars carry it via 6-bit packing (lec_get_serialno decodes frame[0:3]
// through the base64 decode table at .rodata 0xf173 — see legy_sbox.go).
// There is NO magic, NO length field and NO MAC inside the native frame;
// length is implicit (frame length minus 2-byte serial minus 16-byte tag),
// and the 4-byte legy_hmac MAC placement is caller-defined (spec §7).
//
// AES-128-GCM nonce (helper @0x189e8), 12 bytes:
//
//	nonce = ( FILL*10 || BE16(serial) ) XOR baseIV[0:12]
//	FILL  = 0x00 for client->server  (lec_aes_encrypt, w5=1)
//	FILL  = 0xFF for server->client  (lec_aes_encrypt_server, w5=0)
//
// Handshake (lec_handshake_client_start @0x17e58, lec_handshake_server
// @0x17f94, lec_handshake_client_finish @0x18304), all on secp256k1
// (EC_GROUP_new_by_curve_name(NID 714); NOTE: in OpenSSL/BoringSSL NID 714
// is NID_secp256k1 — both hardcoded public keys below verify on secp256k1,
// not on P-256):
//
//	client hello  = base64_raw( serial_LE16 || 00 01 || ephPubComp33 || clientRand16 )   53 B -> 71 chars
//	server reply  = base64_raw( serial_LE16 || serverPubComp33 || serverRand16 || r32 || s32 )  115 B -> 154 chars
//	transcript H  = SHA256( clientPubComp33 || clientRand16 || serverPubComp33 || serverRand16 )
//	signature     = ECDSA-secp256k1 over H with the hardcoded server key (LEGYServerPubKey)
//	session keys  = HKDF-SHA256: PRK = HMAC-SHA256(key=clientRand16||serverRand16, msg=ECDH secret)
//	                OKM = HMAC-SHA256(PRK, "legy fs key" || 0x01)   (KDF helper @0x18af8, label @0xe6d7)
//	                AES-128 key = OKM[16:32], base IV = OKM[0:16]
const (
	// LEGYGCMTAGSize is the appended AES-GCM tag length.
	LEGYGCMTAGSize = 16
	// LEGYHMACSize is the output size of legy_hmac @0x174ec (4-byte MAC).
	LEGYHMACSize = 4
	// LEGYSerialChars is the number of leading wire chars that carry the serial.
	LEGYSerialChars = 3

	// Handshake message shapes (raw bytes and unpadded base64 wire lengths).
	LEGYClientHelloLen     = 53  // serial_LE16 || 00 01 || pubComp33 || rand16
	LEGYClientHelloWireLen = 71  // base64_raw(53 bytes)
	LEGYServerHelloLen     = 115 // serial_LE16 || pubComp33 || rand16 || r32 || s32
	LEGYServerHelloWireLen = 154 // base64_raw(115 bytes)
	LEGYXFSBlobWireLen     = 68  // base64_raw(00 01 || pubComp33 || rand16) = 51 bytes

	// LEGYFillClientToServer is the nonce FILL byte for client->server frames
	// (lec_aes_encrypt @0x186e4).
	LEGYFillClientToServer = 0x00
	// LEGYFillServerToClient is the nonce FILL byte for server->client frames
	// (lec_aes_encrypt_server @0x189d0; lec_aes_decrypt @0x18858).
	LEGYFillServerToClient = 0xFF

	// LEGYFSKeyLabel is the HKDF info label for session keys (.rodata 0xe6d7).
	LEGYFSKeyLabel = "legy fs key"
	// LEGYTempKeyLabel is the HKDF info label for xfs temp keys (.rodata 0xee98).
	LEGYTempKeyLabel = "legy temp key"

	// LEGYDefaultMaxSerialGap is the anti-replay window.
	LEGYDefaultMaxSerialGap = 1024
)

// LEGY errors.
var (
	ErrLEGYReplayDetected = errors.New("legy: replay detected (serial too old)")
	ErrLEGYHMACMismatch   = errors.New("legy: MAC verification failed")
	ErrLEGYShortFrame     = errors.New("legy: frame too short")
	ErrLEGYBadFrame       = errors.New("legy: malformed base64 frame")
	ErrLEGYHandshake      = errors.New("legy: handshake failed")
	ErrLEGYBadSignature   = errors.New("legy: server signature verification failed")
)

// Hardcoded public keys extracted from liblegy.so .rodata (vaddr == file
// offset): LEGYServerPubKey at 0xf273 (handshake ECDSA verify key, loaded by
// lec_handshake_client_finish @0x18474), LEGYXFSPeerPubKey at 0xf130 (static
// "xfs" peer key, lec_prepare_xfs @0x17928). Both are 65-byte uncompressed
// (0x04 || X || Y) secp256k1 points.
const (
	legyServerPubKeyHex  = "04cce101191a5f7b9cc01905602a74faef51f09919980a2669831c1a1b0805888aac06ce1bd376eb4f11227cb59056047b88c40f47666d369160f7c98adfd46ff4"
	legyXFSPeerPubKeyHex = "04f2f529c32550402b08a085f69074cdead32e4b32a1f654f8124f1092d72f04096912e65665d52ece726c86b7d09e83f512aee4083730a4f495c7895fcd57442d"
)

// LEGYServerPubKey is the hardcoded server ECDSA public key used to verify
// handshake replies (liblegy.so .rodata 0xf273).
var LEGYServerPubKey = legyMustHexKey(legyServerPubKeyHex)

// LEGYXFSPeerPubKey is the hardcoded static xfs peer public key
// (liblegy.so .rodata 0xf130).
var LEGYXFSPeerPubKey = legyMustHexKey(legyXFSPeerPubKeyHex)

func legyMustHexKey(h string) [65]byte {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 65 || b[0] != 0x04 {
		panic("legy: bad hardcoded public key constant")
	}
	return [65]byte(b)
}

// ---------------------------------------------------------------------------
// secp256k1 (NID 714) — Go's elliptic.CurveParams assumes a = -3, so secp256k1
// (a = 0) needs its own elliptic.Curve implementation. Affine big.Int math is
// slow but this is a legacy protocol path, not a hot loop.
// ---------------------------------------------------------------------------

type legyK1Curve struct{ params *elliptic.CurveParams }

var (
	legyK1P, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	legyK1N, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	legyK1Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	legyK1Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
)

var legyK1Params = &elliptic.CurveParams{
	Name:    "secp256k1",
	BitSize: 256,
	P:       legyK1P,
	N:       legyK1N,
	B:       big.NewInt(7),
	Gx:      legyK1Gx,
	Gy:      legyK1Gy,
}

// legyCurve is the curve used by every EC op in liblegy.so
// (EC_GROUP_new_by_curve_name(714) == secp256k1).
var legyCurve = legyK1Curve{legyK1Params}

func (c legyK1Curve) Params() *elliptic.CurveParams { return c.params }

func (c legyK1Curve) IsOnCurve(x, y *big.Int) bool {
	if x == nil || y == nil || x.Sign() < 0 || y.Sign() < 0 ||
		x.Cmp(c.params.P) >= 0 || y.Cmp(c.params.P) >= 0 {
		return false
	}
	lhs := new(big.Int).Mul(y, y)
	lhs.Mod(lhs, c.params.P)
	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x)
	rhs.Add(rhs, c.params.B) // a = 0, b = 7
	rhs.Mod(rhs, c.params.P)
	return lhs.Cmp(rhs) == 0
}

func legyModInverse(a, m *big.Int) *big.Int {
	return new(big.Int).ModInverse(new(big.Int).Mod(a, m), m)
}

// Add returns (x1,y1)+(x2,y2); (0,0) denotes the point at infinity.
func (c legyK1Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	p := c.params.P
	if x1.Sign() == 0 && y1.Sign() == 0 {
		return x2, y2
	}
	if x2.Sign() == 0 && y2.Sign() == 0 {
		return x1, y1
	}
	if x1.Cmp(x2) == 0 {
		sum := new(big.Int).Add(y1, y2)
		sum.Mod(sum, p)
		if sum.Sign() == 0 {
			return big.NewInt(0), big.NewInt(0)
		}
		return c.Double(x1, y1)
	}
	lambda := new(big.Int).Sub(y2, y1)
	lambda.Mod(lambda, p)
	lambda.Mul(lambda, legyModInverse(new(big.Int).Sub(x2, x1), p))
	lambda.Mod(lambda, p)
	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, x1)
	x3.Sub(x3, x2)
	x3.Mod(x3, p)
	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(lambda, y3)
	y3.Sub(y3, y1)
	y3.Mod(y3, p)
	return x3, y3
}

func (c legyK1Curve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	p := c.params.P
	if x1.Sign() == 0 && y1.Sign() == 0 {
		return big.NewInt(0), big.NewInt(0)
	}
	if y1.Sign() == 0 {
		return big.NewInt(0), big.NewInt(0)
	}
	lambda := new(big.Int).Mul(x1, x1)
	lambda.Mul(lambda, big.NewInt(3))
	lambda.Mod(lambda, p)
	lambda.Mul(lambda, legyModInverse(new(big.Int).Lsh(y1, 1), p))
	lambda.Mod(lambda, p)
	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, new(big.Int).Lsh(x1, 1))
	x3.Mod(x3, p)
	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(lambda, y3)
	y3.Sub(y3, y1)
	y3.Mod(y3, p)
	return x3, y3
}

func (c legyK1Curve) ScalarMult(x1, y1 *big.Int, k []byte) (*big.Int, *big.Int) {
	x, y := big.NewInt(0), big.NewInt(0)
	for _, b := range k {
		for i := 7; i >= 0; i-- {
			x, y = c.Double(x, y)
			if (b>>uint(i))&1 == 1 {
				x, y = c.Add(x, y, x1, y1)
			}
		}
	}
	return x, y
}

func (c legyK1Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return c.ScalarMult(c.params.Gx, c.params.Gy, k)
}

// legyGenerateKey generates a secp256k1 key pair (EC_KEY_generate_key, NID 714).
func legyGenerateKey() (priv *ecdsa.PrivateKey, err error) {
	return ecdsa.GenerateKey(legyCurve, rand.Reader)
}

// legyPrivFromBytes parses a 32-byte big-endian scalar (BN_bin2bn of state[0:32)).
func legyPrivFromBytes(b []byte) (*ecdsa.PrivateKey, error) {
	if len(b) != 32 {
		return nil, fmt.Errorf("legy: private key len = %d, want 32", len(b))
	}
	d := new(big.Int).SetBytes(b)
	if d.Sign() <= 0 || d.Cmp(legyK1N) >= 0 {
		return nil, errors.New("legy: private scalar out of range")
	}
	x, y := legyCurve.ScalarBaseMult(b)
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: legyCurve, X: x, Y: y},
		D:         d,
	}, nil
}

// legyPubFromUncompressed parses a 65-byte uncompressed point (0x04 || X || Y).
func legyPubFromUncompressed(b []byte) (*ecdsa.PublicKey, error) {
	if len(b) != 65 || b[0] != 0x04 {
		return nil, errors.New("legy: want 65-byte uncompressed point (0x04||X||Y)")
	}
	x := new(big.Int).SetBytes(b[1:33])
	y := new(big.Int).SetBytes(b[33:65])
	if !legyCurve.IsOnCurve(x, y) {
		return nil, errors.New("legy: point not on secp256k1")
	}
	return &ecdsa.PublicKey{Curve: legyCurve, X: x, Y: y}, nil
}

// legyUnmarshalCompressed decodes a 33-byte compressed point. (Go's
// elliptic.UnmarshalCompressed assumes a = -3, so secp256k1 needs its own:
// y² = x³ + 7 mod p, p ≡ 3 mod 4 so sqrt is y2^((p+1)/4).)
func legyUnmarshalCompressed(b []byte) (x, y *big.Int) {
	if len(b) != 33 || (b[0] != 0x02 && b[0] != 0x03) {
		return nil, nil
	}
	x = new(big.Int).SetBytes(b[1:33])
	if x.Cmp(legyK1P) >= 0 {
		return nil, nil
	}
	y2 := new(big.Int).Mul(x, x)
	y2.Mod(y2, legyK1P)
	y2.Mul(y2, x)
	y2.Add(y2, big.NewInt(7))
	y2.Mod(y2, legyK1P)
	exp := new(big.Int).Add(legyK1P, big.NewInt(1))
	exp.Rsh(exp, 2) // (p+1)/4
	y = new(big.Int).Exp(y2, exp, legyK1P)
	check := new(big.Int).Mul(y, y)
	check.Mod(check, legyK1P)
	if check.Cmp(y2) != 0 {
		return nil, nil
	}
	if (y.Bit(0) == 1) != (b[0] == 0x03) {
		y.Sub(legyK1P, y)
	}
	return x, y
}

// legyPubFromCompressed parses a 33-byte compressed point (EC_POINT_oct2point, form=2).
func legyPubFromCompressed(b []byte) (*ecdsa.PublicKey, error) {
	if len(b) != 33 {
		return nil, fmt.Errorf("legy: compressed pub len = %d, want 33", len(b))
	}
	x, y := legyUnmarshalCompressed(b)
	if x == nil {
		return nil, errors.New("legy: invalid compressed point")
	}
	return &ecdsa.PublicKey{Curve: legyCurve, X: x, Y: y}, nil
}

// legyECDH computes the ECDH shared secret: the X coordinate of priv*pub as a
// 32-byte big-endian value (ECDH_compute_key @0x17acc).
func legyECDH(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) ([]byte, error) {
	x, y := legyCurve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	if x.Sign() == 0 && y.Sign() == 0 {
		return nil, errors.New("legy: ECDH point at infinity")
	}
	out := make([]byte, 32)
	xb := x.Bytes()
	copy(out[32-len(xb):], xb)
	return out, nil
}

// ---------------------------------------------------------------------------
// base64 helpers (unpadded RFC 4648, alphabet at liblegy.so .rodata 0xe014)
// ---------------------------------------------------------------------------

func legyB64Encode(raw []byte) []byte {
	out := make([]byte, base64.RawStdEncoding.EncodedLen(len(raw)))
	base64.RawStdEncoding.Encode(out, raw)
	return out
}

// legyB64Decode accepts unpadded (native encoder @0x17b50) or padded base64.
func legyB64Decode(wire []byte) ([]byte, error) {
	w := bytes.TrimSpace(wire)
	if raw, err := base64.RawStdEncoding.DecodeString(string(w)); err == nil {
		return raw, nil
	}
	return base64.StdEncoding.DecodeString(string(w))
}

// ---------------------------------------------------------------------------
// LEGYSession
// ---------------------------------------------------------------------------

// LEGYSession holds the negotiated keys of a LEGY encrypted session.
//
// The native cipher is AES-128-GCM, so only the first 16 bytes of
// EncryptKey/DecryptKey/HMACKey are used (AES key = OKM[16:32]); BaseIV is the
// 16-byte HKDF output OKM[0:16], of which the nonce uses the first 12 bytes.
type LEGYSession struct {
	EncryptKey   [32]byte // AES-128 key for client->server frames (OKM[16:32] in [:16])
	DecryptKey   [32]byte // AES-128 key for server->client frames (same session key)
	HMACKey      [32]byte // key for LEGYHMAC (frame MAC placement is caller-defined)
	BaseIV       [16]byte // OKM[0:16]; nonce = (FILL*10||BE16(serial)) XOR BaseIV[0:12]
	SendSerial   uint32   // only the low 16 bits go on the wire
	RecvMax      uint32
	MaxSerialGap uint32

	// Pending handshake state (lec_handshake_client_start 81-byte state:
	// priv32 || pubComp33 || rand16).
	hsPriv    [32]byte
	hsPubComp [33]byte
	hsRand    [16]byte
	hsSerial  uint16
	hsActive  bool
}

// NewLEGYSession derives session keys from an ECDH shared secret and the
// 32-byte rands value via the native KDF @0x18af8:
//
//	PRK = HMAC-SHA256(key = salt, msg = masterSecret)
//	OKM = HMAC-SHA256(PRK, "legy fs key" || 0x01)        (HKDF-SHA256, outlen 32)
//	AES-128 key = OKM[16:32], base IV = OKM[0:16]
//
// (Equivalent to hkdf.New(sha256.New, secret=masterSecret, salt=salt,
// info="legy fs key") — x/crypto/hkdf computes PRK = HMAC(key=salt,
// msg=secret) and T(1) = HMAC(PRK, info||0x01), matching the native loop.)
func NewLEGYSession(masterSecret, salt []byte) *LEGYSession {
	s := &LEGYSession{MaxSerialGap: LEGYDefaultMaxSerialGap}
	// Best effort; empty inputs leave zero keys (caller error surfaces at GCM time).
	_ = s.deriveSessionKeys(masterSecret, salt)
	return s
}

func (s *LEGYSession) deriveSessionKeys(sharedSecret, rands []byte) error {
	if len(sharedSecret) == 0 || len(rands) == 0 {
		return fmt.Errorf("%w: empty KDF input", ErrLEGYHandshake)
	}
	r := hkdf.New(sha256.New, sharedSecret, rands, []byte(LEGYFSKeyLabel))
	var okm [32]byte
	if _, err := io.ReadFull(r, okm[:]); err != nil {
		return fmt.Errorf("%w: hkdf: %v", ErrLEGYHandshake, err)
	}
	copy(s.EncryptKey[:16], okm[16:32])
	copy(s.DecryptKey[:16], okm[16:32])
	copy(s.HMACKey[:16], okm[:16])
	copy(s.BaseIV[:], okm[:16])
	return nil
}

// ---------------------------------------------------------------------------
// Handshake message layer
// ---------------------------------------------------------------------------

// LEGYHandshakeClientStart generates the ephemeral secp256k1 key pair for a
// LEGY handshake (lec_handshake_client_start @0x17e58). It returns the
// 32-byte private scalar and the 33-byte compressed public point
// (EC_POINT_point2oct, form=2), matching the state layout priv32||pubComp33||rand16.
func LEGYHandshakeClientStart() (privKey, pubKey []byte, err error) {
	key, err := legyGenerateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("legy: secp256k1 keygen: %w", err)
	}
	priv := make([]byte, 32)
	db := key.D.Bytes()
	copy(priv[32-len(db):], db)
	pub := elliptic.MarshalCompressed(legyCurve, key.X, key.Y)
	return priv, pub, nil
}

// LEGYClientHello starts a LEGY handshake on session s: it generates the
// ephemeral key, stores the 81-byte state in s, and returns the client hello
// wire message — base64_raw( serial_LE16 || 00 01 || ephPubComp33 || rand16 ),
// 53 raw bytes -> 71 base64 chars (lec_handshake_client_start @0x17e58; the
// 00 01 prefix is the encoder prefix at .rodata 0xf171).
func LEGYClientHello(s *LEGYSession, serial uint16) (string, error) {
	priv, pubComp, err := LEGYHandshakeClientStart()
	if err != nil {
		return "", err
	}
	copy(s.hsPriv[:], priv)
	copy(s.hsPubComp[:], pubComp)
	if _, err := rand.Read(s.hsRand[:]); err != nil {
		return "", fmt.Errorf("legy: rand: %w", err)
	}
	s.hsSerial = serial
	s.hsActive = true

	hello := make([]byte, LEGYClientHelloLen)
	binary.LittleEndian.PutUint16(hello[0:2], serial)
	hello[2] = 0x00
	hello[3] = 0x01
	copy(hello[4:37], pubComp)
	copy(hello[37:53], s.hsRand[:])
	return string(legyB64Encode(hello)), nil
}

// LEGYServerHello is the parsed server handshake reply
// (lec_handshake_server @0x17f94): base64_raw-decoded 115 bytes =
// serial_LE16 || serverPubComp33 || serverRand16 || r32 || s32 (154 chars).
type LEGYServerHello struct {
	Serial  uint16
	PubComp [33]byte // server ephemeral public key, compressed
	Rand    [16]byte // server random
	R       [32]byte // ECDSA signature r (BN_bn2binpad)
	S       [32]byte // ECDSA signature s
}

// LEGYParseServerHello base64-decodes and parses a 154-char server hello
// (decode loop of lec_handshake_client_finish @0x18358-0x183b4).
func LEGYParseServerHello(wire string) (*LEGYServerHello, error) {
	raw, err := legyB64Decode([]byte(wire))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLEGYBadFrame, err)
	}
	if len(raw) != LEGYServerHelloLen {
		return nil, fmt.Errorf("%w: decoded reply len = %d, want %d", ErrLEGYBadFrame, len(raw), LEGYServerHelloLen)
	}
	h := &LEGYServerHello{Serial: binary.LittleEndian.Uint16(raw[0:2])}
	copy(h.PubComp[:], raw[2:35])
	copy(h.Rand[:], raw[35:51])
	copy(h.R[:], raw[51:83])
	copy(h.S[:], raw[83:115])
	return h, nil
}

// LEGYHandshakeClientFinish completes the client handshake
// (lec_handshake_client_finish @0x18304): it parses the 154-char server
// reply, verifies the ECDSA-secp256k1 signature over
// SHA256(clientPubComp33||clientRand16||serverPubComp33||serverRand16) with
// the hardcoded LEGYServerPubKey, computes the ECDH shared secret, and derives
// the session keys via HKDF-SHA256 with the "legy fs key" label
// (AES-128 key = OKM[16:32], base IV = OKM[0:16]). Call LEGYClientHello first.
func LEGYHandshakeClientFinish(s *LEGYSession, serverHelloWire string) error {
	return legyHandshakeClientFinish(s, serverHelloWire, LEGYServerPubKey[:])
}

func legyHandshakeClientFinish(s *LEGYSession, serverHelloWire string, verifyPub []byte) error {
	if !s.hsActive {
		return fmt.Errorf("%w: no pending client hello (call LEGYClientHello first)", ErrLEGYHandshake)
	}
	sh, err := LEGYParseServerHello(serverHelloWire)
	if err != nil {
		return err
	}
	// Transcript hash H = SHA256(clientPub||clientRand||serverPub||serverRand),
	// all pubs compressed 33-byte (SHA256 updates @0x183e8-0x18430).
	msg := make([]byte, 0, 33+16+33+16)
	msg = append(msg, s.hsPubComp[:]...)
	msg = append(msg, s.hsRand[:]...)
	msg = append(msg, sh.PubComp[:]...)
	msg = append(msg, sh.Rand[:]...)
	if !VerifyLEGYServerSignatureRaw(verifyPub, msg, sh.R[:], sh.S[:]) {
		return fmt.Errorf("%w (ECDSA_do_verify @0x18510)", ErrLEGYBadSignature)
	}
	priv, err := legyPrivFromBytes(s.hsPriv[:])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrLEGYHandshake, err)
	}
	pub, err := legyPubFromCompressed(sh.PubComp[:])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrLEGYHandshake, err)
	}
	shared, err := legyECDH(priv, pub)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrLEGYHandshake, err)
	}
	// KDF data = clientRand16 || serverRand16 (32 bytes, stp q0,q1 @0x185c8).
	rands := make([]byte, 0, 32)
	rands = append(rands, s.hsRand[:]...)
	rands = append(rands, sh.Rand[:]...)
	if err := s.deriveSessionKeys(shared, rands); err != nil {
		return err
	}
	s.hsActive = false
	return nil
}

// VerifyLEGYServerSignature verifies a DER/ASN.1 ECDSA signature over
// SHA256(msg) with a 65-byte uncompressed secp256k1 public key
// (ECDSA_do_verify @0x18510 receives the pre-computed 32-byte digest).
func VerifyLEGYServerSignature(serverPub, msg, sig []byte) bool {
	pub, err := legyPubFromUncompressed(serverPub)
	if err != nil {
		return false
	}
	digest := sha256.Sum256(msg)
	return ecdsa.VerifyASN1(pub, digest[:], sig)
}

// VerifyLEGYServerSignatureRaw verifies a raw (r||s, 32 bytes each) ECDSA
// signature over SHA256(msg), as carried in the server hello reply
// (BN_bin2bn(D+0x33, 32) / BN_bin2bn(D+0x53, 32) @0x184b4/0x184d0).
func VerifyLEGYServerSignatureRaw(serverPub, msg, r, s []byte) bool {
	pub, err := legyPubFromUncompressed(serverPub)
	if err != nil {
		return false
	}
	if len(r) != 32 || len(s) != 32 {
		return false
	}
	digest := sha256.Sum256(msg)
	return ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(r), new(big.Int).SetBytes(s))
}

// ---------------------------------------------------------------------------
// Frame encode/decode: base64_raw( serial_LE16 || ct || tag16 )
// ---------------------------------------------------------------------------

// EncodeFrame packs serial (16-bit LE) and the AES-GCM ct||tag body into the
// base64 wire frame (native encoder @0x17b50 with prefix = serial bytes).
func EncodeFrame(serial uint16, ctTag []byte) []byte {
	buf := make([]byte, 2+len(ctTag))
	binary.LittleEndian.PutUint16(buf[0:2], serial)
	copy(buf[2:], ctTag)
	return legyB64Encode(buf)
}

// DecodeFrame parses a base64 wire frame back into (serial, ct||tag). The
// serial is read exactly like lec_get_serialno @0x182c8: the first 3 wire
// chars through the base64 decode table (equivalent to LE16 of the first two
// decoded bytes for canonical frames).
func DecodeFrame(wire []byte) (uint16, []byte, error) {
	raw, err := legyB64Decode(wire)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %v", ErrLEGYBadFrame, err)
	}
	if len(raw) < 2+LEGYGCMTAGSize {
		return 0, nil, fmt.Errorf("%w: decoded %d bytes, need >= %d", ErrLEGYShortFrame, len(raw), 2+LEGYGCMTAGSize)
	}
	if len(wire) < LEGYSerialChars {
		return 0, nil, ErrLEGYShortFrame
	}
	serial := DecodeSerialBytes([3]byte{wire[0], wire[1], wire[2]})
	return serial, raw[2:], nil
}

// LEGYComputeNonce computes the 12-byte AES-GCM nonce exactly like the helper
// at liblegy.so 0x189e8: 12 bytes of fill with BE16(serial) at bytes [10:12],
// XORed with baseIV[0:12].
//
//	fill = LEGYFillClientToServer (0x00) for client->server frames
//	fill = LEGYFillServerToClient (0xFF) for server->client frames
func LEGYComputeNonce(serial uint16, baseIV [16]byte, fill byte) [12]byte {
	var n [12]byte
	for i := range n {
		n[i] = fill
	}
	n[10] = byte(serial >> 8) // BE16(serial)
	n[11] = byte(serial)
	for i := range n {
		n[i] ^= baseIV[i]
	}
	return n
}

func legyGCM(key16 []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key16)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// encryptFrame seals plaintext with AES-128-GCM (EVP_aes_128_gcm
// @0x1875c, tag appended @0x187ec) and returns the base64 wire frame.
func (s *LEGYSession) encryptFrame(plaintext []byte, fill byte) ([]byte, error) {
	s.SendSerial++
	serial := uint16(s.SendSerial) // 16-bit on the wire; wraps at 65536
	gcm, err := legyGCM(s.EncryptKey[:16])
	if err != nil {
		return nil, err
	}
	nonce := LEGYComputeNonce(serial, s.BaseIV, fill)
	ct := gcm.Seal(nil, nonce[:], plaintext, nil) // ct includes the 16-byte tag
	return EncodeFrame(serial, ct), nil
}

// EncryptLEGYFrame encrypts plaintext into a client->server LEGY wire frame
// (base64( serial_LE16 || ct || tag16 ), nonce FILL = 0x00).
func (s *LEGYSession) EncryptLEGYFrame(plaintext []byte) ([]byte, error) {
	return s.encryptFrame(plaintext, LEGYFillClientToServer)
}

// EncryptLEGYFrameServer encrypts a server->client frame (nonce FILL = 0xFF,
// lec_aes_encrypt_server @0x189d0).
func (s *LEGYSession) EncryptLEGYFrameServer(plaintext []byte) ([]byte, error) {
	return s.encryptFrame(plaintext, LEGYFillServerToClient)
}

func (s *LEGYSession) decryptFrame(wire []byte, fill byte) ([]byte, error) {
	serial, ctTag, err := DecodeFrame(wire)
	if err != nil {
		return nil, err
	}
	if s.RecvMax > 0 && uint32(serial)+s.MaxSerialGap < s.RecvMax {
		return nil, fmt.Errorf("%w: serial=%d max=%d", ErrLEGYReplayDetected, serial, s.RecvMax)
	}
	if uint32(serial) > s.RecvMax {
		s.RecvMax = uint32(serial)
	}
	gcm, err := legyGCM(s.DecryptKey[:16])
	if err != nil {
		return nil, err
	}
	nonce := LEGYComputeNonce(serial, s.BaseIV, fill)
	return gcm.Open(nil, nonce[:], ctTag, nil)
}

// DecryptLEGYFrame decrypts a server->client wire frame received by a client
// (lec_aes_decrypt @0x18858, nonce FILL = 0xFF).
func (s *LEGYSession) DecryptLEGYFrame(wire []byte) ([]byte, error) {
	return s.decryptFrame(wire, LEGYFillServerToClient)
}

// DecryptLEGYFrameServer decrypts a client->server wire frame received by a
// server (lec_aes_decrypt_server @0x189dc, nonce FILL = 0x00).
func (s *LEGYSession) DecryptLEGYFrameServer(wire []byte) ([]byte, error) {
	return s.decryptFrame(wire, LEGYFillClientToServer)
}

// LEGYGetSerialNo extracts the 16-bit serial from a wire frame by decoding
// its first 3 chars through the base64 decode table, exactly like
// lec_get_serialno @0x182c8.
func LEGYGetSerialNo(frame []byte) (uint32, error) {
	if len(frame) < LEGYSerialChars {
		return 0, ErrLEGYShortFrame
	}
	return uint32(DecodeSerialBytes([3]byte{frame[0], frame[1], frame[2]})), nil
}

// ---------------------------------------------------------------------------
// legy_hmac @0x174ec — 4-byte MAC built on XXH32(seed 0)
// ---------------------------------------------------------------------------

// xxHash32 primes (visible as immediates in the transform @0x176a4-0x177e8;
// init words at .rodata 0xf108 = 0x24234428, 0x85EBCA77).
const (
	xxhPrime1 uint32 = 0x9E3779B1
	xxhPrime2 uint32 = 0x85EBCA77
	xxhPrime3 uint32 = 0xC2B2AE3D
	xxhPrime4 uint32 = 0x27D4EB2F
	xxhPrime5 uint32 = 0x165667B1
)

func xxh32Round(acc, lane uint32) uint32 {
	acc += lane * xxhPrime2
	acc = bits.RotateLeft32(acc, 13)
	return acc * xxhPrime1
}

// xxh32 is a pure-Go xxHash32 (seed 0), matching the hash inlined in
// liblegy.so at 0x1764c (init) / 0x176a4 (update) / 0x177e8 (final).
func xxh32(b []byte) uint32 {
	n := len(b)
	i := 0
	var h uint32
	if n >= 16 {
		v1 := xxhPrime1
		v1 += xxhPrime2
		v2 := xxhPrime2
		v3 := uint32(0)
		v4 := uint32(0)
		v4 -= xxhPrime1
		for ; i+16 <= n; i += 16 {
			v1 = xxh32Round(v1, binary.LittleEndian.Uint32(b[i:]))
			v2 = xxh32Round(v2, binary.LittleEndian.Uint32(b[i+4:]))
			v3 = xxh32Round(v3, binary.LittleEndian.Uint32(b[i+8:]))
			v4 = xxh32Round(v4, binary.LittleEndian.Uint32(b[i+12:]))
		}
		h = bits.RotateLeft32(v1, 1) + bits.RotateLeft32(v2, 7) +
			bits.RotateLeft32(v3, 12) + bits.RotateLeft32(v4, 18)
	} else {
		h = xxhPrime5
	}
	h += uint32(n)
	for ; i+4 <= n; i += 4 {
		h += binary.LittleEndian.Uint32(b[i:]) * xxhPrime3
		h = bits.RotateLeft32(h, 17) * xxhPrime4
	}
	for ; i < n; i++ {
		h += uint32(b[i]) * xxhPrime5
		h = bits.RotateLeft32(h, 11) * xxhPrime1
	}
	h ^= h >> 15
	h *= xxhPrime2
	h ^= h >> 13
	h *= xxhPrime3
	h ^= h >> 16
	return h
}

// LEGYHMAC computes the custom 4-byte MAC of liblegy.so's legy_hmac @0x174ec:
//
//	block_ipad = key[0:16] ^ 0x5c*16                  (@0x17550-0x17570)
//	block_opad = block_ipad ^ 0x6a*16 = key ^ 0x36*16 (@0x17578-0x17594, running XOR quirk)
//	inner      = XXH32(block_opad || msg)             (final @0x175b4, stored BE)
//	out        = BE32( XXH32(block_ipad || BE32(inner)) )   (final @0x17630, rev -> BE)
//
// The MAC is not part of the native frame body; its placement in a LEC data
// frame is caller-defined (spec §7).
func LEGYHMAC(key, data []byte) []byte {
	var k [16]byte
	copy(k[:], key)
	var blockIpad, blockOpad [16]byte
	for i := range k {
		blockIpad[i] = k[i] ^ 0x5c
		blockOpad[i] = blockIpad[i] ^ 0x6a // == k[i] ^ 0x36
	}
	inner := make([]byte, 0, 16+len(data))
	inner = append(inner, blockOpad[:]...)
	inner = append(inner, data...)
	var be [4]byte
	binary.BigEndian.PutUint32(be[:], xxh32(inner))
	outer := make([]byte, 0, 20)
	outer = append(outer, blockIpad[:]...)
	outer = append(outer, be[:]...)
	out := make([]byte, LEGYHMACSize)
	binary.BigEndian.PutUint32(out, xxh32(outer))
	return out
}

// LEGYHMACSHA256 is a standard HMAC-SHA256 helper (32-byte MAC) for callers
// that need a conventional MAC outside the native 4-byte legy_hmac.
func LEGYHMACSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// ---------------------------------------------------------------------------
// LEGYTransport — TTransport that carries base64 LEC frames
// ---------------------------------------------------------------------------

// LEGYTransport wraps a TTransport with LEGY frame encryption.
// Write buffers plaintext; Flush encrypts it into one base64 wire frame
// (client->server, FILL=0x00), sends it, then reads the whole response body
// as one server frame (FILL=0xFF) and decrypts it into the read buffer.
type LEGYTransport struct {
	wrapped TTransport
	session *LEGYSession
	wbuf    []byte
	rbuf    []byte
	rpos    int
}

// NewLEGYTransport creates a LEGY-encrypted transport wrapping the given transport.
func NewLEGYTransport(wrapped TTransport, session *LEGYSession) *LEGYTransport {
	return &LEGYTransport{wrapped: wrapped, session: session}
}

func (t *LEGYTransport) Open() error            { return t.wrapped.Open() }
func (t *LEGYTransport) IsOpen() bool           { return t.wrapped.IsOpen() }
func (t *LEGYTransport) Close() error           { return t.wrapped.Close() }
func (t *LEGYTransport) RemainingBytes() uint64 { return t.wrapped.RemainingBytes() }

func (t *LEGYTransport) Write(p []byte) (int, error) {
	t.wbuf = append(t.wbuf, p...)
	return len(p), nil
}

func (t *LEGYTransport) Read(p []byte) (int, error) {
	if t.rpos >= len(t.rbuf) {
		return 0, io.EOF
	}
	n := copy(p, t.rbuf[t.rpos:])
	t.rpos += n
	return n, nil
}

// Flush encrypts the buffered plaintext into a base64 LEGY frame, writes it to
// the underlying transport, flushes, then reads the entire response (one
// base64 server frame) and decrypts it.
func (t *LEGYTransport) Flush(ctx context.Context) error {
	if len(t.wbuf) == 0 {
		return nil
	}
	frame, err := t.session.EncryptLEGYFrame(t.wbuf)
	if err != nil {
		return err
	}
	t.wbuf = t.wbuf[:0]

	if _, err := t.wrapped.Write(frame); err != nil {
		return err
	}
	if cf, ok := t.wrapped.(ContextFlusher); ok {
		if err := cf.Flush(ctx); err != nil {
			return err
		}
	}

	resp, err := io.ReadAll(t.wrapped)
	if err != nil {
		return err
	}
	plain, err := t.session.DecryptLEGYFrame(bytes.TrimSpace(resp))
	if err != nil {
		return err
	}
	t.rbuf = plain
	t.rpos = 0
	return nil
}
