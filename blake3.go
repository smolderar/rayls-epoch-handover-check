package main

import (
	"encoding/binary"
	"math/bits"
)

// Minimal BLAKE3 (default hash mode, 32-byte output). Written from the public spec,
// used only to recompute the epoch digest. Checked against official empty-input and
// one-byte vectors in main_test.go.

var b3iv = [8]uint32{0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19}
var b3perm = [16]int{2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8}

const (
	fChunkStart = 1
	fChunkEnd   = 2
	fParent     = 4
	fRoot       = 8
)

func b3g(s *[16]uint32, a, b, c, d int, mx, my uint32) {
	s[a] = s[a] + s[b] + mx
	s[d] = bits.RotateLeft32(s[d]^s[a], -16)
	s[c] = s[c] + s[d]
	s[b] = bits.RotateLeft32(s[b]^s[c], -12)
	s[a] = s[a] + s[b] + my
	s[d] = bits.RotateLeft32(s[d]^s[a], -8)
	s[c] = s[c] + s[d]
	s[b] = bits.RotateLeft32(s[b]^s[c], -7)
}

func b3round(s *[16]uint32, m *[16]uint32) {
	b3g(s, 0, 4, 8, 12, m[0], m[1])
	b3g(s, 1, 5, 9, 13, m[2], m[3])
	b3g(s, 2, 6, 10, 14, m[4], m[5])
	b3g(s, 3, 7, 11, 15, m[6], m[7])
	b3g(s, 0, 5, 10, 15, m[8], m[9])
	b3g(s, 1, 6, 11, 12, m[10], m[11])
	b3g(s, 2, 7, 8, 13, m[12], m[13])
	b3g(s, 3, 4, 9, 14, m[14], m[15])
}

func b3compress(cv [8]uint32, block [16]uint32, counter uint64, blen uint32, flags uint32) [16]uint32 {
	s := [16]uint32{
		cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
		b3iv[0], b3iv[1], b3iv[2], b3iv[3],
		uint32(counter), uint32(counter >> 32), blen, flags,
	}
	m := block
	for i := 0; i < 7; i++ {
		b3round(&s, &m)
		if i < 6 {
			var p [16]uint32
			for j := 0; j < 16; j++ {
				p[j] = m[b3perm[j]]
			}
			m = p
		}
	}
	for i := 0; i < 8; i++ {
		s[i] ^= s[i+8]
		s[i+8] ^= cv[i]
	}
	return s
}

func b3words(b []byte) [16]uint32 {
	var buf [64]byte
	copy(buf[:], b)
	var w [16]uint32
	for i := 0; i < 16; i++ {
		w[i] = binary.LittleEndian.Uint32(buf[4*i:])
	}
	return w
}

// chunkOut returns the 16-word output of the final block of a chunk (before truncation),
// so the caller can add the ROOT flag only when this chunk is the whole input.
func chunkCV(chunk []byte, counter uint64, root bool) [16]uint32 {
	cv := b3iv
	nblocks := (len(chunk) + 63) / 64
	if nblocks == 0 {
		nblocks = 1
	}
	var out [16]uint32
	for i := 0; i < nblocks; i++ {
		lo := i * 64
		hi := lo + 64
		if hi > len(chunk) {
			hi = len(chunk)
		}
		blk := chunk[lo:hi]
		flags := uint32(0)
		if i == 0 {
			flags |= fChunkStart
		}
		last := i == nblocks-1
		if last {
			flags |= fChunkEnd
			if root {
				flags |= fRoot
			}
		}
		out = b3compress(cv, b3words(blk), counter, uint32(len(blk)), flags)
		if !last {
			copy(cv[:], out[:8])
		}
	}
	return out
}

func b3parent(l, r [8]uint32, root bool) [16]uint32 {
	var blk [16]uint32
	copy(blk[:8], l[:])
	copy(blk[8:], r[:])
	flags := uint32(fParent)
	if root {
		flags |= fRoot
	}
	return b3compress(b3iv, blk, 0, 64, flags)
}

func b3subtree(data []byte, counter uint64) [8]uint32 {
	if len(data) <= 1024 {
		o := chunkCV(data, counter, false)
		var cv [8]uint32
		copy(cv[:], o[:8])
		return cv
	}
	l, r := b3split(data, counter)
	o := b3parent(l, r, false)
	var cv [8]uint32
	copy(cv[:], o[:8])
	return cv
}

func b3split(data []byte, counter uint64) ([8]uint32, [8]uint32) {
	n := (len(data) + 1023) / 1024
	left := 1
	for left*2 < n {
		left *= 2
	}
	ll := left * 1024
	return b3subtree(data[:ll], counter), b3subtree(data[ll:], counter+uint64(left))
}

func blake3Sum(data []byte) [32]byte {
	var o [16]uint32
	if len(data) <= 1024 {
		o = chunkCV(data, 0, true)
	} else {
		l, r := b3split(data, 0)
		o = b3parent(l, r, true)
	}
	var out [32]byte
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint32(out[4*i:], o[i])
	}
	return out
}
