// Copyright (C) 2018-2019 Kdevb0x Ltd.
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

// Package cryptbox is a simple encrypted container for storage of arbitrary files.
package cryptbox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"io"
	"os"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

var (
	ErrFileIOError = errors.New("encountered critical error during file io operation")
)

var SaveDir, _ = os.UserHomeDir()

type Crypter interface {
	Seal(password []byte, salt ...[]byte) error
	Sealed() bool
	Open(password []byte) error
}

// Cryptbox is an abstract object that stores sensitive files securely (for backup).
type Cryptbox struct {
	sums map[[64]byte]file // uses sha-3 SHAKE256 hash for keys

	data uintptr
}

// file is a representation of a filesystem file, it contains the *os.File,
// but also an internal buffer holding the  actual bytes that make up the file.
type file struct {
	Filename string
	Fd       *os.File
	Size     int64
	Buff     *bytes.Buffer // uneeded ATM
}

func NewCryptBox() *Cryptbox {
	// TODO: Create filedes and mmap() with posix_typed_mem_open(filepath string, os.O_RDWR, POSIX_TYPED_MEM_ALLOCATABLE)
	// the goal is to use mmaped data for storage of encrypted data.

	// data, err := unix.Creat(SaveDir, os.ModeExclusive)

	return &Cryptbox{
		sums: make(map[[64]byte]file),
		data: 0,
	}
}

// openFromFilepath opens a file from disk, and creates a file we can use.
func openFromFilepath(path string) (*file, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	size, err := f.Stat()
	if err != nil {
		return nil, err
	}

	file := &file{
		Filename: f.Name(),
		Fd:       f,
		Size:     size.Size(),
		// Buff: *new(bytes.Buffer),
	}
	return file, nil
}

func AddFile(to Crypter, f *file) error {

	// TODO: Finish implementing this.
	// Currently we don't read the bytes from file underlying os.File
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

	cipherReadWriter := gcm.Seal(nil, nonce, buff.Bytes(), nonce)

	// append nonce to encrypted data
	cipherReadWriter = append(cipherReadWriter, nonce...)

}

// packFileByteSlice mimics packFileBuffs but returns a []byte, not bytes.Buffer.
func (b *Cryptbox) packFileByteSlice() ([]byte, error) {
	var totalLen int64
	for _, t := range b.sums {
		totalLen += t.Size
	}
	var tmpb = make([]byte, totalLen)
	// mainbuff := bytes.NewBuffer(tmpb)
	var last int
	for _, tb := range b.sums {
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

// packFileBuffs appends the bytes from each file to the unencrypted buffer,
// making sure to clone each Fd in turn.
func (b *Cryptbox) packFileBuffs() (*bytes.Buffer, error) {
	var totalLen int64
	for _, t := range b.sums {
		totalLen += t.Size
	}
	var tmpb = make([]byte, totalLen)
	mainbuff := bytes.NewBuffer(tmpb)
	for _, tb := range b.sums {
		n, err := io.Copy(mainbuff, tb.Fd)
		if err != nil {
			return nil, ErrFileIOError
		}
		totalLen -= n
		tb.Fd.Close()
	}
	if totalLen != 0 {
		return nil, ErrFileIOError
	}
	return mainbuff, nil
}

func getSHA3Hash(f *file) [64]byte {
	h := sha3.NewShake256()

}
