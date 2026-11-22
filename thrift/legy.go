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
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// LEGYFrameMagic is the 4-byte magic prefix of every LEGY-encrypted frame.
const LEGYFrameMagic = "LEC1"

// LEGY frame header layout:
//
//	[0:4]   magic "LEC1"
//	[4:8]   serial number (uint32, anti-replay)
//	[8:12]  ciphertext length (uint32, includes GCM tag)
//	[12:28] nonce (16 bytes; first 4 = serial, last 12 = GCM nonce)
//	[28:]   AES-256-GCM ciphertext + 16-byte tag, then 32-byte HMAC-SHA256
const (
	LEGYHeaderSize   = 28
	LEGYGCMTAGSize   = 16
	LEGYHMACSize     = 32
	LEGYMinFrameSize = LEGYHeaderSize + LEGYGCMTAGSize + LEGYHMACSize
	// LEGYDefaultMaxSerialGap is the anti-replay window.
	LEGYDefaultMaxSerialGap = 1024
)

// LEGY errors.
var (
	ErrLEGYInvalidMagic   = errors.New("legy: invalid frame magic")
	ErrLEGYReplayDetected = errors.New("legy: replay detected (serial too old)")
	ErrLEGYHMACMismatch   = errors.New("legy: HMAC verification failed")
	ErrLEGYShortFrame     = errors.New("legy: frame too short")
	ErrLEGYHandshake      = errors.New("legy: handshake failed")
)

// LEGYSession holds negotiated keys for a LEGY encrypted session.
type LEGYSession struct {
	EncryptKey   [32]byte
	DecryptKey   [32]byte
	HMACKey      [32]byte
	SendSerial   uint32
	RecvMax      uint32
	MaxSerialGap uint32
}

// NewLEGYSession derives session keys from a master secret via HKDF-SHA256.
func NewLEGYSession(masterSecret, salt []byte) *LEGYSession {
	s := &LEGYSession{MaxSerialGap: LEGYDefaultMaxSerialGap}
	r := hkdf.New(sha256.New, masterSecret, salt, []byte("legy-session-keys"))
	buf := make([]byte, 32)
	io.ReadFull(r, buf)
	copy(s.EncryptKey[:], buf)
	io.ReadFull(r, buf)
	copy(s.DecryptKey[:], buf)
	io.ReadFull(r, buf)
	copy(s.HMACKey[:], buf)
	return s
}

// LEGYHandshakeClientStart generates an X25519 key pair for the LEGY handshake.
func LEGYHandshakeClientStart() (privKey, pubKey []byte, err error) {
	privKey = make([]byte, 32)
	if _, err = rand.Read(privKey); err != nil {
		return nil, nil, fmt.Errorf("legy: rand: %w", err)
	}
	pubKey, err = curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("legy: x25519: %w", err)
	}
	return privKey, pubKey, nil
}

// LEGYHandshakeClientFinish completes the handshake using the server's public key.
func LEGYHandshakeClientFinish(privKey, serverPubKey []byte) (*LEGYSession, error) {
	shared, err := curve25519.X25519(privKey, serverPubKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLEGYHandshake, err)
	}
	return NewLEGYSession(shared, serverPubKey), nil
}

// LEGYHMAC computes HMAC-SHA256.
func LEGYHMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// EncryptLEGYFrame encrypts plaintext into a LEGY frame.
func (s *LEGYSession) EncryptLEGYFrame(plaintext []byte) ([]byte, error) {
	s.SendSerial++
	serial := s.SendSerial

	totalLen := LEGYHeaderSize + len(plaintext) + LEGYGCMTAGSize + LEGYHMACSize
	frame := make([]byte, totalLen)
	copy(frame[0:4], LEGYFrameMagic)
	binary.BigEndian.PutUint32(frame[4:8], serial)
	binary.BigEndian.PutUint32(frame[8:12], uint32(len(plaintext)+LEGYGCMTAGSize))

	nonce := frame[12:28]
	binary.BigEndian.PutUint32(nonce[0:4], serial)
	if _, err := rand.Read(nonce[4:16]); err != nil {
		return nil, fmt.Errorf("legy: nonce: %w", err)
	}

	block, err := aes.NewCipher(s.EncryptKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce[4:16], plaintext, frame[0:12])
	copy(frame[LEGYHeaderSize:], ct)

	mac := LEGYHMAC(s.HMACKey[:], frame[0:LEGYHeaderSize+len(ct)])
	copy(frame[LEGYHeaderSize+len(ct):], mac)
	return frame, nil
}

// DecryptLEGYFrame decrypts a LEGY frame back to plaintext.
func (s *LEGYSession) DecryptLEGYFrame(frame []byte) ([]byte, error) {
	if len(frame) < LEGYMinFrameSize {
		return nil, ErrLEGYShortFrame
	}
	if string(frame[0:4]) != LEGYFrameMagic {
		return nil, ErrLEGYInvalidMagic
	}
	serial := binary.BigEndian.Uint32(frame[4:8])
	if s.RecvMax > 0 && serial+s.MaxSerialGap < s.RecvMax {
		return nil, fmt.Errorf("%w: serial=%d max=%d", ErrLEGYReplayDetected, serial, s.RecvMax)
	}
	if serial > s.RecvMax {
		s.RecvMax = serial
	}
	ctLen := int(binary.BigEndian.Uint32(frame[8:12]))
	if ctLen < LEGYGCMTAGSize || LEGYHeaderSize+ctLen+LEGYHMACSize > len(frame) {
		return nil, fmt.Errorf("legy: bad ct length %d", ctLen)
	}
	ct := frame[LEGYHeaderSize : LEGYHeaderSize+ctLen]
	mac := frame[LEGYHeaderSize+ctLen:]
	if !hmac.Equal(mac, LEGYHMAC(s.HMACKey[:], frame[0:LEGYHeaderSize+ctLen])) {
		return nil, ErrLEGYHMACMismatch
	}
	block, err := aes.NewCipher(s.DecryptKey[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, frame[16:28], ct, frame[0:12])
}

// LEGYGetSerialNo extracts the serial from a LEGY frame header.
func LEGYGetSerialNo(frame []byte) (uint32, error) {
	if len(frame) < 8 {
		return 0, ErrLEGYShortFrame
	}
	if string(frame[0:4]) != LEGYFrameMagic {
		return 0, ErrLEGYInvalidMagic
	}
	return binary.BigEndian.Uint32(frame[4:8]), nil
}

// LEGYTransport wraps a TTransport with LEGY frame encryption.
// Write buffers plaintext; Flush encrypts + sends via the underlying transport.
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

func (t *LEGYTransport) Open() error                       { return t.wrapped.Open() }
func (t *LEGYTransport) IsOpen() bool                      { return t.wrapped.IsOpen() }
func (t *LEGYTransport) Close() error                      { return t.wrapped.Close() }
func (t *LEGYTransport) RemainingBytes() uint64            { return t.wrapped.RemainingBytes() }

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

// Flush encrypts the buffered plaintext into a LEGY frame, writes it to the
// underlying transport, flushes it, then reads + decrypts the response.
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

	// Read response frame: header first, then body
	hdr := make([]byte, LEGYHeaderSize)
	if _, err := io.ReadFull(t.wrapped, hdr); err != nil {
		return err
	}
	ctLen := int(binary.BigEndian.Uint32(hdr[8:12]))
	body := make([]byte, ctLen+LEGYHMACSize)
	if _, err := io.ReadFull(t.wrapped, body); err != nil {
		return err
	}
	full := append(hdr, body...)

	plain, err := t.session.DecryptLEGYFrame(full)
	if err != nil {
		return err
	}
	t.rbuf = plain
	t.rpos = 0
	return nil
}
