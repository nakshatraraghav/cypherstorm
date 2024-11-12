package encryption

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

type XChaCha20Poly1305Encryptor struct{}

func NewXChaCha20Poly1305Encryptor() *XChaCha20Poly1305Encryptor {
	return &XChaCha20Poly1305Encryptor{}
}

func (e *XChaCha20Poly1305Encryptor) Encrypt(reader io.Reader, writer io.Writer, key []byte) error {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("failed to create XChaCha20-Poly1305: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Write nonce
	if err := binary.Write(writer, binary.LittleEndian, uint32(len(nonce))); err != nil {
		return err
	}
	if _, err := writer.Write(nonce); err != nil {
		return err
	}

	// Process in chunks
	buf := make([]byte, 64*1024) // 64KB chunks
	for {
		n, err := reader.Read(buf)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		encrypted := aead.Seal(nil, nonce, buf[:n], nil)
		if err := binary.Write(writer, binary.LittleEndian, uint32(len(encrypted))); err != nil {
			return err
		}
		if _, err := writer.Write(encrypted); err != nil {
			return err
		}
	}

	return nil
}

func (e *XChaCha20Poly1305Encryptor) Decrypt(reader io.Reader, writer io.Writer, key []byte) error {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return fmt.Errorf("failed to create XChaCha20-Poly1305: %w", err)
	}

	var nonceSize uint32
	if err := binary.Read(reader, binary.LittleEndian, &nonceSize); err != nil {
		return err
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(reader, nonce); err != nil {
		return err
	}

	for {
		var chunkSize uint32
		err := binary.Read(reader, binary.LittleEndian, &chunkSize)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		encrypted := make([]byte, chunkSize)
		if _, err := io.ReadFull(reader, encrypted); err != nil {
			return err
		}

		decrypted, err := aead.Open(nil, nonce, encrypted, nil)
		if err != nil {
			return err
		}

		if _, err := writer.Write(decrypted); err != nil {
			return err
		}
	}

	return nil
}
