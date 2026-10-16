// epochscan: read-only check of Rayls epoch handover records.
//
// For every epoch it calls rayls_epochRecord on a public RPC, then checks on its own:
//  1. signer bitmap (base58 + roaring) -> how many of the outgoing committee signed
//  2. quorum rule floor(2n/3)+1
//  3. the aggregate BLS signature (BLS12-381 min-sig, DST from the Axyl source) with a pairing check
//  4. the epoch digest recomputed from the record (blake3 over bcs bytes) vs the certificate hash
//  5. parent_hash chain between consecutive records
//  6. committee continuity: committee(e) == next_committee(e-1)
//
// It sends no transactions and needs no key or funds. Raw answers are saved so a rerun works offline.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

const dstG1 = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"
const b58alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var errNotFound = errors.New("not found")

type Record struct {
	Epoch         uint64   `json:"epoch"`
	Committee     []string `json:"committee"`
	NextCommittee []string `json:"next_committee"`
	ParentHash    string   `json:"parent_hash"`
	ParentState   struct {
		Number uint64 `json:"number"`
		Hash   string `json:"hash"`
	} `json:"parent_state"`
	ParentConsensus string `json:"parent_consensus"`
}

type Cert struct {
	EpochHash         string `json:"epoch_hash"`
	Signature         string `json:"signature"`
	SignedAuthorities string `json:"signed_authorities"`
}

type Epoch struct {
	Rec  Record
	Cert Cert
}

// ---------- base58 ----------

func b58(s string) ([]byte, error) {
	n := new(big.Int)
	base := big.NewInt(58)
	for _, c := range s {
		i := strings.IndexRune(b58alpha, c)
		if i < 0 {
			return nil, fmt.Errorf("bad base58 char %q", c)
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(i)))
	}
	z := 0
	for z < len(s) && s[z] == '1' {
		z++
	}
	return append(make([]byte, z), n.Bytes()...), nil
}

// ---------- roaring bitmap (portable format) ----------

func roaringValues(b []byte) (vals []uint32, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("roaring decode: %v", r)
		}
	}()
	u16 := func(p int) int { return int(binary.LittleEndian.Uint16(b[p:])) }
	if len(b) < 8 {
		return nil, errors.New("roaring: too short")
	}
	cookie := binary.LittleEndian.Uint32(b[0:4])
	var size, p int
	var hasRun bool
	var runBM []byte
	switch {
	case cookie&0xFFFF == 12347:
		hasRun = true
		size = int(cookie>>16) + 1
		p = 4
		nb := (size + 7) / 8
		runBM = b[p : p+nb]
		p += nb
	case cookie == 12346:
		size = int(binary.LittleEndian.Uint32(b[4:8]))
		p = 8
	default:
		return nil, fmt.Errorf("roaring: unknown cookie %d", cookie)
	}
	keys := make([]int, size)
	cards := make([]int, size)
	for i := 0; i < size; i++ {
		keys[i] = u16(p)
		cards[i] = u16(p+2) + 1
		p += 4
	}
	if !hasRun || size >= 4 {
		p += 4 * size
	}
	for i := 0; i < size; i++ {
		hi := uint32(keys[i]) << 16
		isRun := hasRun && runBM[i/8]&(1<<(uint(i)%8)) != 0
		switch {
		case isRun:
			nr := u16(p)
			p += 2
			for j := 0; j < nr; j++ {
				start, l := u16(p), u16(p+2)
				p += 4
				for v := start; v <= start+l; v++ {
					vals = append(vals, hi|uint32(v))
				}
			}
		case cards[i] > 4096:
			for w := 0; w < 1024; w++ {
				word := binary.LittleEndian.Uint64(b[p+8*w:])
				for bit := 0; bit < 64; bit++ {
					if word>>uint(bit)&1 == 1 {
						vals = append(vals, hi|uint32(w*64+bit))
					}
				}
			}
			p += 8192
		default:
			for j := 0; j < cards[i]; j++ {
				vals = append(vals, hi|uint32(u16(p+2*j)))
			}
			p += 2 * cards[i]
		}
	}
	return vals, nil
}

// ---------- BLS ----------

var pkCache = map[string]bls.G2Affine{}

func parsePK(s string) (bls.G2Affine, error) {
	if p, ok := pkCache[s]; ok {
		return p, nil
	}
	var p bls.G2Affine
	b, err := b58(s)
	if err != nil {
		return p, err
	}
	if len(b) != 96 {
		return p, fmt.Errorf("public key is %d bytes, expected 96", len(b))
	}
	if _, err := p.SetBytes(b); err != nil {
		return p, err
	}
	pkCache[s] = p
	return p, nil
}

func parseSig(s string) (bls.G1Affine, error) {
	var p bls.G1Affine
	b, err := b58(s)
	if err != nil {
		return p, err
	}
	if len(b) != 48 {
		return p, fmt.Errorf("signature is %d bytes, expected 48", len(b))
	}
	_, err = p.SetBytes(b)
	return p, err
}

// verifyAgg checks e(sig, g2) == e(H(msg), sum(pks)), i.e. the same test as blst aggregate_verify
// when every signer signed the same message.
func verifyAgg(sig bls.G1Affine, pks []bls.G2Affine, msg []byte) bool {
	if len(pks) == 0 {
		return false
	}
	h, err := bls.HashToG1(msg, []byte(dstG1))
	if err != nil {
		return false
	}
	var agg bls.G2Jac
	for i := range pks {
		var j bls.G2Jac
		j.FromAffine(&pks[i])
		agg.AddAssign(&j)
	}
	var aggA bls.G2Affine
	aggA.FromJacobian(&agg)
	_, _, _, g2 := bls.Generators()
	var ng2 bls.G2Affine
	ng2.Neg(&g2)
	ok, err := bls.PairingCheck([]bls.G1Affine{sig, h}, []bls.G2Affine{ng2, aggA})
	return err == nil && ok
}

func hex32(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(s), "0x"))
	if err != nil || len(b) != 32 {
		return nil, fmt.Errorf("bad 32-byte hex %q", s)
	}
	return b, nil
}

// checkSig tries the (few) plausible encodings of the signed message and committee order, and
// reports which one verified. The intent prefix is scope=EpochBoundary(1), version=0, app=Consensus(1).
func checkSig(rec Record, cert Cert, idx []int) string {
	sig, err := parseSig(cert.Signature)
	if err != nil {
		return "bad-signature-bytes"
	}
	h, err := hex32(cert.EpochHash)
	if err != nil {
		return "bad-hash"
	}
	orders := []struct {
		name string
		list []string
	}{{"as-returned", rec.Committee}}
	sorted := append([]string(nil), rec.Committee...)
	sort.Slice(sorted, func(i, j int) bool {
		a, _ := b58(sorted[i])
		b, _ := b58(sorted[j])
		return bytes.Compare(a, b) < 0
	})
	orders = append(orders, struct {
		name string
		list []string
	}{"sorted-bytes", sorted})
	msgs := []struct {
		name string
		b    []byte
	}{
		{"intent+hash", append([]byte{1, 0, 1}, h...)},
		{"intent+len+hash", append([]byte{1, 0, 1, 0x20}, h...)},
	}
	for _, o := range orders {
		var pks []bls.G2Affine
		okAll := true
		for _, i := range idx {
			if i < 0 || i >= len(o.list) {
				okAll = false
				break
			}
			pk, err := parsePK(o.list[i])
			if err != nil {
				okAll = false
				break
			}
			pks = append(pks, pk)
		}
		if !okAll {
			continue
		}
		for _, m := range msgs {
			if verifyAgg(sig, pks, m.b) {
				return "VALID (" + o.name + ", " + m.name + ")"
			}
		}
	}
	return "NOT VERIFIED"
}

// ---------- digest recompute: blake3(bcs(EpochRecord)) ----------

func uleb(n int) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n != 0 {
			out = append(out, b|0x80)
		} else {
			return append(out, b)
		}
	}
}

func bcsRecord(r Record, epochBytes int, pkPrefix, hashPrefix bool) ([]byte, error) {
	var out []byte
	switch epochBytes {
	case 4:
		out = binary.LittleEndian.AppendUint32(out, uint32(r.Epoch))
	default:
		out = binary.LittleEndian.AppendUint64(out, r.Epoch)
	}
	putKeys := func(ks []string) error {
		out = append(out, uleb(len(ks))...)
		for _, k := range ks {
			b, err := b58(k)
			if err != nil {
				return err
			}
			if pkPrefix {
				out = append(out, uleb(len(b))...)
			}
			out = append(out, b...)
		}
		return nil
	}
	putHash := func(s string) error {
		b, err := hex32(s)
		if err != nil {
			return err
		}
		if hashPrefix {
			out = append(out, 0x20)
		}
		out = append(out, b...)
		return nil
	}
	if err := putKeys(r.Committee); err != nil {
		return nil, err
	}
	if err := putKeys(r.NextCommittee); err != nil {
		return nil, err
	}
	if err := putHash(r.ParentHash); err != nil {
		return nil, err
	}
	out = binary.LittleEndian.AppendUint64(out, r.ParentState.Number)
	if err := putHash(r.ParentState.Hash); err != nil {
		return nil, err
	}
	if err := putHash(r.ParentConsensus); err != nil {
		return nil, err
	}
	return out, nil
}

func checkDigest(rec Record, cert Cert) string {
	want, err := hex32(cert.EpochHash)
	if err != nil {
		return "bad-hash"
	}
	for _, eb := range []int{4, 8} {
		for _, pp := range []bool{true, false} {
			for _, hp := range []bool{true, false} {
				enc, err := bcsRecord(rec, eb, pp, hp)
				if err != nil {
					continue
				}
				got := blake3Sum(enc)
				if bytes.Equal(got[:], want) {
					return fmt.Sprintf("MATCH (epoch u%d, key-len=%v, hash-len=%v)", eb*8, pp, hp)
				}
			}
		}
	}
	return "no match"
}

// ---------- RPC ----------

func rpcCall(url, method string, params []any) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	var last error
	for try := 0; try < 3; try++ {
		cl := &http.Client{Timeout: 25 * time.Second}
		resp, err := cl.Post(url, "application/json", bytes.NewReader(body))
		if err != nil {
			last = err
			time.Sleep(time.Second)
			continue
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var r struct {
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			last = fmt.Errorf("bad json (HTTP %d): %.120s", resp.StatusCode, raw)
			time.Sleep(time.Second)
			continue
		}
		if r.Error != nil {
			if strings.Contains(strings.ToLower(r.Error.Message), "not found") || strings.Contains(strings.ToLower(r.Error.Message), "notfound") {
				return nil, errNotFound
			}
			return nil, fmt.Errorf("rpc error %d: %s", r.Error.Code, r.Error.Message)
		}
		if string(r.Result) == "null" {
			return nil, errNotFound
		}
		return r.Result, nil
	}
	return nil, last
}

func loadEpoch(url, dir string, e uint64, offline bool) (*Epoch, error) {
	path := filepath.Join(dir, fmt.Sprintf("epoch_%04d.json", e))
	raw, err := os.ReadFile(path)
	if err != nil {
		if offline {
			return nil, errNotFound
		}
		raw, err = rpcCall(url, "rayls_epochRecord", []any{e})
		if err != nil {
			return nil, err
		}
		_ = os.WriteFile(path, raw, 0o644)
		time.Sleep(120 * time.Millisecond)
	}
	var pair []json.RawMessage
	if err := json.Unmarshal(raw, &pair); err != nil || len(pair) != 2 {
		return nil, fmt.Errorf("epoch %d: unexpected result shape", e)
	}
	var ep Epoch
	if err := json.Unmarshal(pair[0], &ep.Rec); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(pair[1], &ep.Cert); err != nil {
		return nil, err
	}
	return &ep, nil
}
