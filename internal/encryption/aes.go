package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

type AesGcmEncryptor struct {
	key []byte
}

func NewAesGcmEncryptor(key []byte) *AesGcmEncryptor {
	return &AesGcmEncryptor{
		key: key,
	}
}

func (e *AesGcmEncryptor) Encrypt(reader io.Reader, writer io.Writer) error {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate and write the nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Write nonce size and nonce to the output
	err = binary.Write(writer, binary.LittleEndian, uint32(len(nonce)))
	if err != nil {
		return fmt.Errorf("failed to write nonce size: %w", err)
	}

	_, err = writer.Write(nonce)
	if err != nil {
		return fmt.Errorf("failed to write nonce: %w", err)
	}

	// Encrypt data in chunks
	chunkSize := 1024 * 64 // 64 KB, adjust for memory/performance needs
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

		// Encrypt the chunk; here we use `Seal` which includes the tag for each chunk
		ciphertext = gcm.Seal(nil, nonce, buffer[:n], nil)
		if _, err := writer.Write(ciphertext); err != nil {
			return fmt.Errorf("failed to write ciphertext: %w", err)
		}
	}

	return nil
}

func (e *AesGcmEncryptor) Decrypt(reader io.Reader, writer io.Writer) error {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM: %w", err)
	}

	// Read the nonce size and nonce
	var nonceSize uint32
	if err := binary.Read(reader, binary.LittleEndian, &nonceSize); err != nil {
		return fmt.Errorf("failed to read nonce size: %w", err)
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(reader, nonce); err != nil {
		return fmt.Errorf("failed to read nonce: %w", err)
	}

	// Decrypt data in chunks
	chunkSize := 1024*64 + gcm.Overhead() // Adjust for the GCM tag size per chunk
	buffer := make([]byte, chunkSize)

	for {
		n, err := reader.Read(buffer)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read ciphertext: %w", err)
		}
		if n == 0 {
			break
		}

		// Decrypt the chunk
		plaintext, err := gcm.Open(nil, nonce, buffer[:n], nil)
		if err != nil {
			return fmt.Errorf("decryption failed: %w", err)
		}

		// Write decrypted data to the output writer
		if _, err := writer.Write(plaintext); err != nil {
			return fmt.Errorf("failed to write plaintext: %w", err)
		}
	}

	return nil
}
