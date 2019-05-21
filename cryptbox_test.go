// Copyright (C) 2018-2019 Kdevb0x Ltd.
// This software may be modified and distributed under the terms
// of the MIT license.  See the LICENSE file for details.

package cryptbox

import (
	"testing"
)

func BenchmarkPackFileByteSlice(b *testing.B) {
	box := NewCryptbox()
	for n := 0; n < b.N; n++ {
		box.packFileByteSlice()
	}
}
