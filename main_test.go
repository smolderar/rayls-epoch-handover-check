package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

// testDataDir points at a folder of saved epoch_NNNN.json answers (set EPOCH_TESTDATA, default ./testdata).
func testDataDir() string {
	if d := os.Getenv("EPOCH_TESTDATA"); d != "" {
		return d
	}
	return "testdata"
}

func b58enc(b []byte) string {
	n := new(big.Int).SetBytes(b)
	base := big.NewInt(58)
	var out []byte
	mod := new(big.Int)
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		out = append(out, b58alpha[mod.Int64()])
	}
	for _, c := range b {
		if c != 0 {
			break
		}
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func TestBlake3Vectors(t *testing.T) {
	h := blake3Sum(nil)
	if hex.EncodeToString(h[:]) != "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262" {
		t.Fatalf("empty input vector failed: %x", h)
	}
	h = blake3Sum([]byte{0})
	if hex.EncodeToString(h[:]) != "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213" {
		t.Fatalf("1-byte vector failed: %x", h)
	}
}

// the signer bitmap string copied from the real epoch 160 certificate (screen recording)
func TestRealBitmap(t *testing.T) {
	b, err := b58("CfEZsDc8fopkwXaJSVco2MtM383wPXPZzawzspmtj")
	if err != nil {
		t.Fatal(err)
	}
	v, err := roaringValues(b)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(v) != "[0 1 2 3 4 5 6]" {
		t.Fatalf("got %v", v)
	}
}

func roaringEncode(vals []int) []byte {
	b := binary.LittleEndian.AppendUint32(nil, 12346)
	b = binary.LittleEndian.AppendUint32(b, 1)
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(vals)-1))
	b = binary.LittleEndian.AppendUint32(b, 16)
	for _, v := range vals {
		b = binary.LittleEndian.AppendUint16(b, uint16(v))
	}
	return b
}

type valkey struct {
	sk fr.Element
	pk []byte
}

func newKey(seed int64) valkey {
	var k valkey
	k.sk.SetBigInt(big.NewInt(seed*7919 + 12345))
	var bi big.Int
	k.sk.BigInt(&bi)
	_, _, _, g2 := bls.Generators()
	var p bls.G2Affine
	p.ScalarMultiplication(&g2, &bi)
	pb := p.Bytes()
	k.pk = pb[:]
	return k
}

func sign(k valkey, msg []byte) bls.G1Affine {
	h, _ := bls.HashToG1(msg, []byte(dstG1))
	var bi big.Int
	k.sk.BigInt(&bi)
	var s bls.G1Affine
	s.ScalarMultiplication(&h, &bi)
	return s
}

func buildChain(t *testing.T) map[uint64]json.RawMessage {
	keys := make([]valkey, 9)
	for i := range keys {
		keys[i] = newKey(int64(i + 1))
	}
	sortedCommittee := func(ids []int) ([]valkey, []string) {
		ks := make([]valkey, 0, len(ids))
		for _, i := range ids {
			ks = append(ks, keys[i])
		}
		sort.Slice(ks, func(i, j int) bool { return string(ks[i].pk) < string(ks[j].pk) })
		ss := make([]string, len(ks))
		for i := range ks {
			ss[i] = b58enc(ks[i].pk)
		}
		return ks, ss
	}
	setFor := func(e int) []int {
		if e >= 3 { // committee changes at epoch 3: validator 6 -> 7
			return []int{0, 1, 2, 3, 4, 5, 7}
		}
		return []int{0, 1, 2, 3, 4, 5, 6}
	}
	out := map[uint64]json.RawMessage{}
	prevHash := strings.Repeat("00", 32)
	for e := 0; e <= 5; e++ {
		ks, cs := sortedCommittee(setFor(e))
		_, ns := sortedCommittee(setFor(e + 1))
		rec := Record{Epoch: uint64(e), Committee: cs, NextCommittee: ns, ParentHash: "0x" + prevHash}
		rec.ParentState.Number = uint64(1000 + e*172800)
		rec.ParentState.Hash = "0x" + strings.Repeat("ab", 32)
		rec.ParentConsensus = "0x" + strings.Repeat("cd", 32)
		enc, err := bcsRecord(rec, 4, true, true)
		if err != nil {
			t.Fatal(err)
		}
		d := blake3Sum(enc)
		prevHash = hex.EncodeToString(d[:])
		signers := []int{0, 1, 2, 3, 4, 5, 6}
		if e == 4 {
			signers = []int{0, 1, 2, 3} // below quorum (needs 5 of 7)
		}
		if e == 2 {
			signers = []int{0, 1, 2, 4, 6}
		}
		msg := append([]byte{1, 0, 1, 0x20}, d[:]...)
		var agg bls.G1Jac
		for _, i := range signers {
			s := sign(ks[i], msg)
			var j bls.G1Jac
			j.FromAffine(&s)
			agg.AddAssign(&j)
		}
		var aggA bls.G1Affine
		aggA.FromJacobian(&agg)
		sb := aggA.Bytes()
		cert := Cert{EpochHash: "0x" + prevHash, Signature: b58enc(sb[:]), SignedAuthorities: b58enc(roaringEncode(signers))}
		pair, _ := json.Marshal([]any{rec, cert})
		out[uint64(e)] = pair
	}
	return out
}

func TestEndToEnd(t *testing.T) {
	chain := buildChain(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		switch req.Method {
		case "rayls_nodeStatus":
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"epoch":6}}`)
		case "rayls_epochRecord":
			e := uint64(req.Params[0].(float64))
			if raw, ok := chain[e]; ok {
				fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":%s}`, raw)
			} else {
				fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"NotFound"}}`)
			}
		}
	}))
	defer srv.Close()
	dir := t.TempDir()
	if os.Getenv("MOCKOUT") != "" {
		dir = os.Getenv("MOCKOUT")
		os.MkdirAll(dir, 0o755)
	}
	var prev *Epoch
	var rows []Row
	for e := uint64(0); e <= 6; e++ {
		cur, err := loadEpoch(srv.URL, dir, e, false)
		if err != nil {
			if e == 6 && err == errNotFound {
				break
			}
			t.Fatalf("epoch %d: %v", e, err)
		}
		r := analyse(cur, prev)
		rows = append(rows, r)
		t.Logf("%+v", r)
		prev = cur
	}
	if len(rows) != 6 {
		t.Fatalf("rows=%d", len(rows))
	}
	for i, r := range rows {
		if !strings.HasPrefix(r.Digest, "MATCH") {
			t.Errorf("epoch %d digest: %s", i, r.Digest)
		}
		wantSig := "VALID"
		if i == 4 {
			wantSig = "BELOW QUORUM"
		}
		if !strings.HasPrefix(r.Sig, wantSig) {
			t.Errorf("epoch %d sig: %s want %s", i, r.Sig, wantSig)
		}
		if i > 0 && (r.Chain != "ok" || r.Continuity != "ok") {
			t.Errorf("epoch %d chain/continuity: %s %s", i, r.Chain, r.Continuity)
		}
		if i == 3 && !r.Changed {
			t.Errorf("epoch 3 should show committee change")
		}
		if i != 3 && r.Changed {
			t.Errorf("epoch %d should not show change", i)
		}
	}
	// tamper test: flip one signer index in epoch 1 -> must NOT verify
	cur, _ := loadEpoch(srv.URL, dir, 1, true)
	bad := *cur
	bad.Cert.SignedAuthorities = b58enc(roaringEncode([]int{0, 1, 2, 3, 4, 5}))
	r := analyse(&bad, nil)
	if strings.HasPrefix(r.Sig, "VALID") {
		t.Errorf("tampered signer set must not verify, got %s", r.Sig)
	}
	bad2 := *cur
	bad2.Cert.EpochHash = "0x" + strings.Repeat("11", 32)
	r = analyse(&bad2, nil)
	if strings.HasPrefix(r.Sig, "VALID") || strings.HasPrefix(r.Digest, "MATCH") {
		t.Errorf("tampered hash must not pass: %s / %s", r.Sig, r.Digest)
	}
}

func TestKeccak(t *testing.T) {
	k := keccak256(nil)
	if hex.EncodeToString(k[:]) != "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" {
		t.Fatalf("keccak256 empty: %x", k)
	}
	want := map[int]string{
		0:   "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
		3:   "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
		768: "",
	}
	inputs := map[int][]byte{0: nil, 3: []byte("abc")}
	big := []byte{}
	for i := 0; i < 3; i++ {
		for j := 0; j < 256; j++ {
			big = append(big, byte(j))
		}
	}
	inputs[768] = big
	want[768] = os.Getenv("SHA3_768")
	for n, in := range inputs {
		h := sha3_256(in)
		if want[n] != "" && hex.EncodeToString(h[:]) != want[n] {
			t.Fatalf("sha3 len %d: %x", n, h)
		}
	}
	if selector("transfer(address,uint256)") != "a9059cbb" {
		t.Fatalf("selector wrong: %s", selector("transfer(address,uint256)"))
	}
}

func TestRealEpochs(t *testing.T) {
	dir := testDataDir()
	if _, err := os.Stat(dir); err != nil {
		t.Skip("no real data")
	}
	e159, err := loadEpoch("", dir, 159, true)
	if err != nil {
		t.Fatal(err)
	}
	e160, err := loadEpoch("", dir, 160, true)
	if err != nil {
		t.Fatal(err)
	}
	r := analyse(e160, e159)
	t.Logf("%+v", r)
	if !strings.HasPrefix(r.Sig, "VALID") || !strings.HasPrefix(r.Digest, "MATCH") || r.Chain != "ok" {
		t.Fatalf("real epoch 160 failed: %+v", r)
	}
	var buf strings.Builder
	out = &buf
	tamperTests(e160, e159)
	out = os.Stdout
	t.Log("\n" + buf.String())
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	for _, l := range lines[2:] {
		if strings.Contains(l, "valid") || strings.Contains(l, "match") && !strings.Contains(l, "no-match") {
			t.Fatalf("tamper case passed but must fail: %s", l)
		}
	}
}

func TestDecodeValidators(t *testing.T) {
	dir := testDataDir()
	if _, err := os.Stat(dir); err != nil {
		t.Skip("no real data")
	}
	e160, _ := loadEpoch("", dir, 160, true)
	w := func(v int) []byte { b := make([]byte, 32); big.NewInt(int64(v)).FillBytes(b); return b }
	var tuples [][]byte
	for i, k := range e160.Rec.Committee[:3] {
		kb, _ := b58(k)
		var tup []byte
		tup = append(tup, w(8*32)...)
		addr := make([]byte, 32)
		addr[31] = byte(0xa0 + i)
		tup = append(tup, addr...)
		for j := 0; j < 6; j++ {
			tup = append(tup, w(0)...)
		}
		tup = append(tup, w(len(kb))...)
		tup = append(tup, kb...) // 96 bytes = 3 words, already aligned
		tuples = append(tuples, tup)
	}
	var enc []byte
	enc = append(enc, w(32)...)
	enc = append(enc, w(len(tuples))...)
	off := 32 * len(tuples)
	for _, tp := range tuples {
		enc = append(enc, w(off)...)
		off += len(tp)
	}
	for _, tp := range tuples {
		enc = append(enc, tp...)
	}
	vals, err := decodeValidators(enc)
	if err != nil || len(vals) != 3 {
		t.Fatalf("decode: %v %d", err, len(vals))
	}
	m, hit := matchCommittee(e160.Rec.Committee, vals)
	if hit != 3 || m[e160.Rec.Committee[1]] != "0x00000000000000000000000000000000000000a1" {
		t.Fatalf("match: %d %v", hit, m)
	}
}

// ---- registry snapshot with a mock registry (7 active, one more validator pending) ----

func encValidators(keys [][]byte, addrs []byte, acts, status []int) []byte {
	w := func(v int) []byte { b := make([]byte, 32); big.NewInt(int64(v)).FillBytes(b); return b }
	var tuples [][]byte
	for i, kb := range keys {
		var tup []byte
		tup = append(tup, w(8*32)...)
		a := make([]byte, 32)
		a[31] = addrs[i]
		tup = append(tup, a...)
		tup = append(tup, w(acts[i])...)
		tup = append(tup, w(0)...)
		tup = append(tup, w(status[i])...)
		tup = append(tup, w(0)...)
		tup = append(tup, w(0)...)
		tup = append(tup, w(0)...)
		tup = append(tup, w(len(kb))...)
		tup = append(tup, kb...)
		tuples = append(tuples, tup)
	}
	var enc []byte
	enc = append(enc, w(32)...)
	enc = append(enc, w(len(tuples))...)
	off := 32 * len(tuples)
	for _, tp := range tuples {
		enc = append(enc, w(off)...)
		off += len(tp)
	}
	for _, tp := range tuples {
		enc = append(enc, tp...)
	}
	return enc
}

func TestRegistrySnapshot(t *testing.T) {
	dir := testDataDir()
	if _, err := os.Stat(dir); err != nil {
		t.Skip("no real data")
	}
	e160, _ := loadEpoch("", dir, 160, true)
	var keys [][]byte
	for _, k := range e160.Rec.Committee {
		kb, _ := b58(k)
		keys = append(keys, kb)
	}
	// an eighth, unrelated valid key
	var sc fr.Element
	sc.SetUint64(12345)
	var bi big.Int
	sc.BigInt(&bi)
	_, _, _, g2 := bls.Generators()
	var g2j bls.G2Jac
	g2j.FromAffine(&g2)
	g2j.ScalarMultiplication(&g2j, &bi)
	var g2a bls.G2Affine
	g2a.FromJacobian(&g2j)
	b8 := g2a.Bytes()
	keys8 := append(append([][]byte{}, keys...), b8[:])

	ceSel := selector("getCurrentEpoch()")
	comSel := selector("getCommitteeValidators(uint32)")
	valSel := selector("getValidators(uint8)")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
			Params []any  `json:"params"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		call := req.Params[0].(map[string]any)["data"].(string)[2:]
		sel := call[:8]
		var res []byte
		switch sel {
		case ceSel:
			res = make([]byte, 32)
			res[31] = 169
		case comSel:
			ep, _ := new(big.Int).SetString(call[8:], 16)
			n := 7
			if ep.Int64() >= 171 {
				n = 8
			}
			addrs := []byte{1, 2, 3, 4, 5, 6, 7, 8}
			res = encValidators(keys8[:n], addrs[:n], make([]int, n), make([]int, n))
		case valSel:
			addrs := []byte{1, 2, 3, 4, 5, 6, 7, 8}
			acts := []int{0, 0, 0, 0, 0, 0, 0, 170}
			st := []int{3, 3, 3, 3, 3, 3, 3, 2}
			res = encValidators(keys8, addrs, acts, st)
		}
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":"0x%s"}`, hex.EncodeToString(res))
	}))
	defer srv.Close()
	var buf bytes.Buffer
	old := out
	out = &buf
	defer func() { out = old }()
	registrySnapshot(srv.URL, map[uint64]*Epoch{}, map[string]string{})
	got := buf.String()
	t.Log("\n" + got)
	for _, want := range []string{
		"getCurrentEpoch() = 169",
		"getCommitteeValidators(170): 7 validators",
		"getCommitteeValidators(171): 8 validators",
		"not in the committee of epoch 169: 0x0000000000000000000000000000000000000008",
		"all unretired validators, 8 listed",
		"PendingActivation",
		"activation epoch 170",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q", want)
		}
	}
}
