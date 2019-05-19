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
	"io"
	"os"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
)

// data holds encrypted data after calling Seal.
type data []byte

// Read reads data into p. It returns the number of bytes read into p. The
// bytes are taken from at most one Read on the underlying Reader, hence n
// may be less than len(p). To read exactly len(p) bytes, use
// io.ReadFull(b, p). At EOF, the count will be zero and err will be
// io.EOF.
func (d *data) Read(p []byte) (n int, err error) {
	n = copy(p, *d)
	*d = (*d)[n:]
	if n == 0 {
		err = io.EOF
	}
	return n, err
}

func (d *data) Write(p []byte) (n int, err error)

// File represents a single data item to be stored in a Cryptbox.
type File struct {
	Filename string
	fd       *os.File

	// The unencrypted, raw file checksum
	FileChecksum []byte
	buff         data
}

type Cryptboxer interface {
	Seal(password []byte, salt ...[]byte) error
	Sealed() bool
	Unseal([]byte) error
}

type ArbitraryStorage struct {
	Start   uintptr
	End     uintptr
	offsets []uint64
}

// Cryptbox is an encryptable container of arbitrary files.
type Cryptbox struct {
	// map filename, to key:value pairs
	Metadata map[string]map[string]string

	Storage ArbitraryStorage
}

func (b *Cryptbox) AddFile(file *File) {

}
func OpenFileFromPath(path string) (*File, error) {
	f, err := os.Open(path)
	if err != nil {
		if err.(error) == os.ErrNotExist {
			return nil, errors.New("file not found")
		}
		return nil, err
	}
	// var fbuff bytes.Buffer
	var stat, _ = f.Stat()
	var fbuff = make(data, stat.Size(), stat.Size()*2)
	var file = &File{
		Filename: f.Name(),
		fd:       f,

		buff: fbuff,
	}
	//TODO: hash file.ReadWriter

	return file, nil
}

func NewCryptbox() *Cryptbox {

}
func (b *Cryptbox) Seal(password []byte, salt ...[]byte) error {
	var storageLen int
	for _, f := range b.Contents {
		storageLen += len(f.ReadWriter)
	}
	// create random nonce
	var nonce = make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	key, err := bcrypt.GenerateFromPassword(pw, 14)
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
	var buff bytes.Buffer
	for _, bt := range b.Contents {
		buff.Write(bt.ReadWriter)
	}
	cipherReadWriter := gcm.Seal(nil, nonce, buff.Bytes(), nil)

	// append nonce to encrypted data
	cipherReadWriter = append(cipherReadWriter, nonce...)

}
