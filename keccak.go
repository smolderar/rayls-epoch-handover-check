package main

import (
	"encoding/binary"
	"math/bits"
)

// Minimal Keccak-256 (Ethereum flavour, pad byte 0x01). Used for ABI function selectors and to test
// the RPC doc's claim that the epoch record digest is keccak256(encode(record)).

var keccakRC = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}
var keccakRot = [24]int{1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44}
var keccakPi = [24]int{10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1}

func keccakF(st *[25]uint64) {
	var bc [5]uint64
	for r := 0; r < 24; r++ {
		for i := 0; i < 5; i++ {
			bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20]
		}
		for i := 0; i < 5; i++ {
			t := bc[(i+4)%5] ^ bits.RotateLeft64(bc[(i+1)%5], 1)
			for j := 0; j < 25; j += 5 {
				st[j+i] ^= t
			}
		}
		t := st[1]
		for i := 0; i < 24; i++ {
			j := keccakPi[i]
			tmp := st[j]
			st[j] = bits.RotateLeft64(t, keccakRot[i])
			t = tmp
		}
		for j := 0; j < 25; j += 5 {
			for i := 0; i < 5; i++ {
				bc[i] = st[j+i]
			}
			for i := 0; i < 5; i++ {
				st[j+i] ^= (^bc[(i+1)%5]) & bc[(i+2)%5]
			}
		}
		st[0] ^= keccakRC[r]
	}
}

func sponge256(data []byte, pad byte) [32]byte {
	const rate = 136
	var st [25]uint64
	msg := append([]byte(nil), data...)
	padLen := rate - len(msg)%rate
	p := make([]byte, padLen)
	p[0] = pad
	p[padLen-1] |= 0x80
	msg = append(msg, p...)
	for off := 0; off < len(msg); off += rate {
		for i := 0; i < rate/8; i++ {
			st[i] ^= binary.LittleEndian.Uint64(msg[off+8*i:])
		}
		keccakF(&st)
	}
	var out [32]byte
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(out[8*i:], st[i])
	}
	return out
}

func keccak256(data []byte) [32]byte { return sponge256(data, 0x01) }
func sha3_256(data []byte) [32]byte  { return sponge256(data, 0x06) }
