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
	buff     data
	// The unencrypted, raw file checksum
	FileChecksum []byte
}

// Len returns the files size on disk. In order to avoid passing an addition
// return value, Len will return -1 in the event of an error.
func (f *File) Len() int64 {
	s, err := f.fd.Stat()
	if err != nil {
		return -1
	}
	return s.Size()
}

type Cryptboxer interface {
	Seal(password []byte, salt ...[]byte) error
	Sealed() bool
	Unseal([]byte) error
}

type ArbitraryStorage struct {
	Start   uintptr
	End     uintptr
	offsets map[[]byte]uint64 // maps filename to offset
}

// Cryptbox is an encryptable container of arbitrary files.
type Cryptbox struct {
	// any additional metadata
	Metadata map[string]string

	Storage ArbitraryStorage
}

func (b *Cryptbox) AddFile(file *File) error {
	if filelength := file.Len(); filelength <= 0 {
		return errors.New("unable to add file to cryptbox: invalid length")
	}
	// 	b.Storage.offsets[file.Filename] =
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
	n, err := io.ReadFull(f, file.buff)
	if err != nil {
		return nil, err
	}
	if n != file.Len() {
		return nil, io.ErrShortWrite
	}
	file.FileChecksum = getcrc32(file)
	return file, nil
}

func getcrc32(f *File) uint32 {
	newcrc := crc32.ChecksumIEEE(f.buff)
}

func NewCryptbox() *Cryptbox {
	var storage = ArbitraryStorage{}
	cbox := &Cryptbox{
		Metadata: make(map[string]string),
		Storage:  storage,
	}
	cbox.Storage.Start = uintptr(unsafe.Pointer(&cbox.Storage))
	return &cbox
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
