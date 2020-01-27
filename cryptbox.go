// Copyright (C) 2018-2019 Kdevb0x Ltd.
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

// Package cryptbox is a simple encrypted container for storage of arbitrary files.
package cryptbox

import (
	"crypto/rand"
	"io"
	"io/ioutil"
	"path/filepath"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/sha3"

	"github.com/awnumar/memguard"
)

type Crypter interface {
	Seal(password []byte, salt ...[]byte) error
	Sealed() bool
	Open(password []byte) error
	AddFile(path string) error
}

// file is a representation of a filesystem file, it contains the *os.File,
// but also an internal buffer holding the  actual bytes that make up the file.
type File struct {
	Filename string
	buff     []byte
	Size     int64
}

// NewFileFromPath opens a file from disk, and creates a file we can use.
func NewFileFromPath(path string) (*File, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	size := len(b)

	_, file := filepath.Split(path)
	f := &File{
		Filename: file,
		Size:     int64(size),
		// Buff: *new(bytes.Buffer),
		buff: b,
	}
	return f, nil
}

func (f *File) SHA3Hash() [64]byte {
	var digest [64]byte
	sha3.ShakeSum256(digest[:], f.buff)
	return digest

}

type FileMetadata struct {
	Hash   [64]byte
	Offset int
	F      *File
}

// Cryptbox is an abstract object that stores sensitive files securely (for backup).
type Cryptbox struct {
	Sums []FileMetadata // uses sha-3 SHAKE256 hash for keys

	Data   *memguard.Enclave
	pwhash []byte
	sealed bool
}

func NewCryptBox() *Cryptbox {

	var b *Cryptbox
	b.Sums = make([]FileMetadata, 0)
	var totSize int
	for _, f := range b.Sums {
		totSize += int(f.F.Size)
	}
	b.Data = memguard.NewEnclaveRandom(totSize)
	return b
}

func (b *Cryptbox) AddFile(path string) error {

	f, err := NewFileFromPath(path)
	if err != nil {
		return err
	}
	hash := f.SHA3Hash()
	meta := FileMetadata{
		Hash: hash,
		F:    f,
	}
	b.Sums = append(b.Sums, meta)

	return nil
}

func (b *Cryptbox) Seal(password []byte) error {
	var c = make(chan error)

	go func(c chan error) {

		bf, err := b.Data.Open()
		if err != nil {
			c <- err
		}
		bf.Wipe()
		if !bf.IsMutable() {
			bf.Melt()
		}
		var lastoff = 0
		for i, f := range b.Sums {
			size := f.F.Size
			b.Sums[i].Offset = lastoff

			bf.Lock()
			bf.MoveAt(lastoff, f.F.buff)
			bf.Unlock()

			lastoff += int(size) + 1
		}
		b.Data = bf.Seal()
		close(c)
	}(c)

	// create random nonce
	var nonce = make([]byte, 12)

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	key, err := bcrypt.GenerateFromPassword(password, 14)
	if err != nil {
		return err
	}
	b.pwhash = key

	// wait for goroutine; if it reports an error, return it
	if err, isErr := <-c; isErr {
		return err
	}

	// if we got here, gouroutine closed the chan and all is well.
	b.sealed = true
	return nil

}

func (b *Cryptbox) IsSealed() bool {
	if b.Data.Size() > 0 && len(b.pwhash) > 0 {
		if b.sealed {
			return true
		}
	}
	return false
}

/*
// TODO: Finish implementing Open.

func (b *Cryptbox) Open(password []byte) error {
	if !b.IsSealed() {
		return errors.New("error: failed to open; already open")
	}
	if err := bcrypt.CompareHashAndPassword(b.pwhash, password); err != nil {
		return err
	}
	buff, err := b.Data.Open()
	if err != nil {
		return err
	}
	b.sealed = false
	return nil

}
*/
