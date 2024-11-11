package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

type AesGcmEncryptor struct{}

func NewAesGcmEncryptor() Encryptor {
	return &AesGcmEncryptor{}
}

func (e *AesGcmEncryptor) Encrypt(reader io.Reader, writer io.Writer, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	err = binary.Write(writer, binary.LittleEndian, uint32(len(nonce)))
	if err != nil {
		return fmt.Errorf("failed to write nonce size: %w", err)
	}

	_, err = writer.Write(nonce)
	if err != nil {
		return fmt.Errorf("failed to write nonce: %w", err)
	}

	chunkSize := 64 * 1024
	buffer := make([]byte, chunkSize)
	var ciphertext []byte

	for {
		n, err := reader.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read plaintext: %w", err)
		}
		if n == 0 {
			break
		}

		ciphertext = gcm.Seal(nil, nonce, buffer[:n], nil)
		if _, err := writer.Write(ciphertext); err != nil {
			return fmt.Errorf("failed to write ciphertext: %w", err)
		}
	}

	return nil
}

func (e *AesGcmEncryptor) Decrypt(reader io.Reader, writer io.Writer, key []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	var nonceSize uint32
	if err := binary.Read(reader, binary.LittleEndian, &nonceSize); err != nil {
		return fmt.Errorf("failed to read nonce size: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(reader, nonce); err != nil {
		return fmt.Errorf("failed to read nonce: %w", err)
	}

	chunkSize := 1024*64 + gcm.Overhead()
	buffer := make([]byte, chunkSize)

	for {
		n, err := reader.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read ciphertext: %w", err)
		}
		if n == 0 {
			break
		}

		plaintext, err := gcm.Open(nil, nonce, buffer[:n], nil)
		if err != nil {
			return fmt.Errorf("decryption failed: %w", err)
		}

		if _, err := writer.Write(plaintext); err != nil {
			return fmt.Errorf("failed to write plaintext: %w", err)
		}
	}

	return nil
}
