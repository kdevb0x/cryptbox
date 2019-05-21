// Copyright (C) 2018-2019 Kdevb0x Ltd.
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package cryptbox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"unsafe"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

var (
	ErrFileIOError = errors.New("encountered critical error during file IO operation")
)

type Crypter interface {
	Seal(password []byte, salt ...[]byte) error
	Sealed() bool
	Unseal(password []byte) error
}

type Jsonmeta struct {
	Filename string `json:"filename"`
}

// Cryptbox is an abstract object that stores sensitive files securely (for backup).
type Cryptbox struct {
	Metadata map[uint32]FileRepr // crc32 checksum to file metadata
	data     unsafe.Pointer
}

// FileRepr is a representation of a filesystem file, it contains the *os.File,
// but also an internal buffer holding the  actual bytes that make up the file.
type FileRepr struct {
	Filename string
	Fd       *os.File
	Size     int64
	// Buff     bytes.Buffer  // uneeded ATM
}

func NewCryptBox() *Cryptbox {
	return &Cryptbox{
		Metadata: make(map[uint32]FileRepr),
		data:     nil,
	}
}

// OpenFromFilepath opens a file from disk, and creates a FileRepr we can use.
func OpenFromFilepath(path string) (*FileRepr, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	size, err := f.Stat()
	if err != nil {
		return nil, err
	}

	file := &FileRepr{
		Filename: f.Name(),
		Fd:       f,
		Size:     size.Size(),
		// Buff: *new(bytes.Buffer),
	}
	return file, nil
}

func (b *Cryptbox) AddFile(f *FileRepr) error {

	// TODO: Finish implementing this.
	// Currently we don't read the bytes from FileRepr underlying os.File
	// untill we iterate throught the Metadat map, but we need a []byte in
	// order to hash for the maps key, so kind of a chicken before egg issue.

}
func (b *Cryptbox) Seal(password []byte) error {
	// create random nonce
	var nonce = make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	key, err := bcrypt.GenerateFromPassword(password, 14)
	if err != nil {
		return err
	}
	dk := pbkdf2.Key(key, nonce, 4096, 32, sha512.New)

	block, err := aes.NewCipher(dk)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	// pack each File contiguously

	cipherReadWriter := gcm.Seal(nil, nonce, buff.Bytes(), nil)

	// append nonce to encrypted data
	cipherReadWriter = append(cipherReadWriter, nonce...)

}

// packFileByteSlice mimics packFileBuffs but returns a []byte, not bytes.Buffer.
func (b *Cryptbox) packFileByteSlice() ([]byte, error) {
	var totalLen int64
	for _, t := range b.Metadata {
		totalLen += t.Size
	}
	var tmpb = make([]byte, totalLen)
	// mainbuff := bytes.NewBuffer(tmpb)
	var last int
	for _, tb := range b.Metadata {
		// n, err := io.Copy(mainbuff, tb.Fd)
		// if err != nil {
		// 	return ErrFileIOError
		// }
		// totalLen -= n
		n, err := io.ReadFull(tb.Fd, tmpb[last:tb.Size])
		if err != nil {
			if e := err.(error); e == io.ErrUnexpectedEOF {
				// tb.Fd.Read(tmpb[last:tb.Size])
				return nil, e
			}
			return nil, err
		}
		last += n
		tb.Fd.Close()

	}
	if last != len(tmpb) {
		return nil, ErrFileIOError
	}
	return tmpb, nil

}

// packFileBuffs appends the bytes from each FileRepr to the pre-encrypted buffer,
// making sure to clone each Fd in turn.
func (b *Cryptbox) packFileBuffs() (*bytes.Buffer, error) {
	var totalLen int64
	for _, t := range b.Metadata {
		totalLen += t.Size
	}
	var tmpb = make([]byte, totalLen)
	mainbuff := bytes.NewBuffer(tmpb)
	for _, tb := range b.Metadata {
		n, err := io.Copy(mainbuff, tb.Fd)
		if err != nil {
			return nil, ErrFileIOError
		}
		totalLen -= n
		tb.Fd.Close()
	}
	if totalLen != 0 {
		return ErrFileIOError
	}
	return nil
}

func getcrc32(f *FileRepr) uint32 {
	return crc32.ChecksumIEEE(f.Buff.Bytes())
}
