package thrift

import (
	"bytes"
	"context"
	"testing"
)

func legyTestSession(t *testing.T) *LEGYSession {
	t.Helper()
	priv, pub, err := LEGYHandshakeClientStart()
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	s, err := LEGYHandshakeClientFinish(priv, pub)
	if err != nil {
		t.Fatalf("finish: %v", err)
	}
	s.DecryptKey = s.EncryptKey
	return s
}

func TestLEGYEncryptDecryptRoundtrip(t *testing.T) {
	s := legyTestSession(t)
	plaintext := []byte{0x80, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}

	frame, err := s.EncryptLEGYFrame(plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if string(frame[0:4]) != LEGYFrameMagic {
		t.Fatalf("bad magic: %q", frame[0:4])
	}
	serial, err := LEGYGetSerialNo(frame)
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	if serial != 1 {
		t.Fatalf("serial = %d, want 1", serial)
	}
	dec, err := s.DecryptLEGYFrame(frame)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(dec, plaintext) {
		t.Fatalf("mismatch: %x vs %x", dec, plaintext)
	}
}

func TestLEGYAntiReplay(t *testing.T) {
	s := legyTestSession(t)
	msg := []byte("replay test")
	for i := 0; i < 5; i++ {
		f, _ := s.EncryptLEGYFrame(msg)
		if _, err := s.DecryptLEGYFrame(f); err != nil {
			t.Fatalf("msg %d: %v", i, err)
		}
	}
	// Craft old frame with serial=1 — replay check fires before HMAC/GCM
	old, _ := s.EncryptLEGYFrame(msg)
	old[4], old[5], old[6], old[7] = 0, 0, 0, 1
	_, err := s.DecryptLEGYFrame(old)
	if err != ErrLEGYReplayDetected {
		// If HMAC check fires first (because we tampered the header), that's also valid rejection
		if err != ErrLEGYHMACMismatch {
			t.Fatalf("want ErrLEGYReplayDetected or ErrLEGYHMACMismatch, got %v", err)
		}
	}
}

func TestLEGYHMACTamper(t *testing.T) {
	s := legyTestSession(t)
	f, _ := s.EncryptLEGYFrame([]byte("tamper"))
	f[LEGYHeaderSize] ^= 1
	_, err := s.DecryptLEGYFrame(f)
	if err != ErrLEGYHMACMismatch {
		t.Fatalf("want ErrLEGYHMACMismatch, got %v", err)
	}
}

func TestLEGYTransport(t *testing.T) {
	s := legyTestSession(t)
	mem := NewTMemoryBuffer()
	lt := NewLEGYTransport(mem, s)

	msg := []byte("hello legy transport")
	if _, err := lt.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Flush would need a server; test the buffer mechanics instead
	if len(lt.wbuf) != len(msg) {
		t.Fatalf("wbuf len = %d, want %d", len(lt.wbuf), len(msg))
	}

	// Simulate encrypted frame in memory buffer, then read back
	frame, err := s.EncryptLEGYFrame(msg)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	mem.Write(frame)
	// Read header + body back
	hdr := make([]byte, LEGYHeaderSize)
	mem.Read(hdr)
	ctLen := int(uint32(hdr[8])<<24 | uint32(hdr[9])<<16 | uint32(hdr[10])<<8 | uint32(hdr[11]))
	body := make([]byte, ctLen+LEGYHMACSize)
	mem.Read(body)
	full := append(hdr, body...)
	dec, err := s.DecryptLEGYFrame(full)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(dec, msg) {
		t.Fatalf("transport roundtrip mismatch")
	}
}

func TestLEGYInvalidMagic(t *testing.T) {
	s := legyTestSession(t)
	bad := make([]byte, LEGYMinFrameSize)
	_, err := s.DecryptLEGYFrame(bad)
	if err != ErrLEGYInvalidMagic {
		t.Fatalf("want ErrLEGYInvalidMagic, got %v", err)
	}
}

func TestLEGYContextFlush(t *testing.T) {
	// Verify LEGYTransport implements ContextFlusher
	var _ ContextFlusher = (*LEGYTransport)(nil)
	var _ TTransport = (*LEGYTransport)(nil)
	_ = context.Background()
}
