package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

const registryAddr = "0x07e17e17e17e17e17e17e17e17e17e17e17e17e1"

var out io.Writer = os.Stdout

func pf(format string, a ...any) { fmt.Fprintf(out, format, a...) }

// ---------- per-epoch analysis ----------

type Row struct {
	Epoch      uint64
	N, K, Quor int
	Idx        []int
	Sig        string
	Digest     string
	Chain      string
	Continuity string
	Changed    bool
	Blocks     uint64
	Err        string
	// checkpoint block (parent_state) seen by the RPC node and by the explorer
	RPCBlock string
	ExpBlock string
	Closed   int64
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}

func signerIdx(c Cert) ([]int, error) {
	bm, err := b58(c.SignedAuthorities)
	if err != nil {
		return nil, err
	}
	vals, err := roaringValues(bm)
	if err != nil {
		return nil, err
	}
	idx := make([]int, 0, len(vals))
	for _, v := range vals {
		idx = append(idx, int(v))
	}
	sort.Ints(idx)
	return idx, nil
}

func analyse(cur, prev *Epoch) (row Row) {
	row.Epoch = cur.Rec.Epoch
	defer func() {
		if r := recover(); r != nil {
			row.Err = fmt.Sprint(r)
		}
	}()
	row.N = len(cur.Rec.Committee)
	row.Quor = row.N*2/3 + 1
	idx, err := signerIdx(cur.Cert)
	if err != nil {
		row.Err = "bitmap: " + err.Error()
		return
	}
	row.Idx = idx
	row.K = len(idx)
	row.Digest = checkDigest(cur.Rec, cur.Cert)
	if row.K < row.Quor {
		row.Sig = "BELOW QUORUM"
	} else {
		row.Sig = checkSig(cur.Rec, cur.Cert, row.Idx)
	}
	row.Chain, row.Continuity = "-", "-"
	if prev != nil {
		if strings.EqualFold(cur.Rec.ParentHash, prev.Cert.EpochHash) {
			row.Chain = "ok"
		} else {
			row.Chain = "BREAK"
		}
		if sameSet(cur.Rec.Committee, prev.Rec.NextCommittee) {
			row.Continuity = "ok"
		} else {
			row.Continuity = "BREAK"
		}
		row.Changed = !sameSet(cur.Rec.Committee, prev.Rec.Committee)
		if cur.Rec.ParentState.Number >= prev.Rec.ParentState.Number {
			row.Blocks = cur.Rec.ParentState.Number - prev.Rec.ParentState.Number
		}
	}
	return
}

func firstWord(s string) string {
	switch {
	case strings.HasPrefix(s, "VALID"):
		return "valid"
	case strings.HasPrefix(s, "MATCH"):
		return "match"
	case s == "":
		return "-"
	}
	return strings.ToUpper(strings.ReplaceAll(s, " ", "-"))
}

func short(k string) string {
	if len(k) > 8 {
		return k[:8]
	}
	return k
}

// ---------- checkpoint block: RPC node and public explorer ----------

type BlockInfo struct {
	Hash string
	Time int64
	Err  string
}

func cached(path string, fetch func() ([]byte, error), offline bool) ([]byte, error) {
	if raw, err := os.ReadFile(path); err == nil {
		return raw, nil
	}
	if offline {
		return nil, errors.New("offline")
	}
	raw, err := fetch()
	if err != nil {
		return nil, err
	}
	_ = os.WriteFile(path, raw, 0o644)
	return raw, nil
}

func rpcBlock(url, dir string, n uint64, offline bool) BlockInfo {
	raw, err := cached(filepath.Join(dir, fmt.Sprintf("block_rpc_%d.json", n)), func() ([]byte, error) {
		return rpcCall(url, "eth_getBlockByNumber", []any{fmt.Sprintf("0x%x", n), false})
	}, offline)
	if err != nil {
		return BlockInfo{Err: err.Error()}
	}
	var b struct {
		Hash      string `json:"hash"`
		Timestamp string `json:"timestamp"`
	}
	if json.Unmarshal(raw, &b) != nil || b.Hash == "" {
		return BlockInfo{Err: "bad block json"}
	}
	t, _ := strconv.ParseInt(strings.TrimPrefix(b.Timestamp, "0x"), 16, 64)
	return BlockInfo{Hash: b.Hash, Time: t}
}

func explorerBlock(base, dir string, n uint64, offline bool) BlockInfo {
	raw, err := cached(filepath.Join(dir, fmt.Sprintf("block_explorer_%d.json", n)), func() ([]byte, error) {
		var last error
		for try := 0; try < 4; try++ {
			cl := &http.Client{Timeout: 20 * time.Second}
			resp, err := cl.Get(fmt.Sprintf("%s/api/v2/blocks/%d", strings.TrimRight(base, "/"), n))
			if err != nil {
				last = err
				time.Sleep(time.Second)
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return body, nil
			}
			last = fmt.Errorf("HTTP %d", resp.StatusCode)
			time.Sleep(time.Duration(1+try) * time.Second)
		}
		return nil, last
	}, offline)
	if err != nil {
		return BlockInfo{Err: err.Error()}
	}
	var b struct {
		Hash      string `json:"hash"`
		Timestamp string `json:"timestamp"`
	}
	if json.Unmarshal(raw, &b) != nil || b.Hash == "" {
		return BlockInfo{Err: "bad explorer json"}
	}
	t, err := time.Parse(time.RFC3339Nano, b.Timestamp)
	if err != nil {
		return BlockInfo{Hash: b.Hash}
	}
	return BlockInfo{Hash: b.Hash, Time: t.Unix()}
}

func cmpBlock(want string, b BlockInfo) string {
	switch {
	case b.Err != "":
		return "n/a"
	case strings.EqualFold(want, b.Hash):
		return "same"
	default:
		return "DIFF"
	}
}

// ---------- ConsensusRegistry (onchain committee) ----------

func selector(sig string) string {
	h := keccak256([]byte(sig))
	return hex.EncodeToString(h[:4])
}

func ethCall(url, data string) ([]byte, error) {
	raw, err := rpcCall(url, "eth_call", []any{map[string]string{"to": registryAddr, "data": data}, "latest"})
	if err != nil {
		return nil, err
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return hex.DecodeString(strings.TrimPrefix(s, "0x"))
}

type RegVal struct {
	Key     bls.G2Affine
	Hex     string
	Addr    string
	Valid   bool
	ActEp   uint64
	ExitEp  uint64
	Status  int
	Retired bool
}

var statusNames = map[int]string{0: "Undefined", 1: "Staked", 2: "PendingActivation", 3: "Active", 4: "PendingExit", 5: "Exited", 6: "Any"}

func registryCurrentEpoch(url string) (uint64, error) {
	b, err := ethCall(url, "0x"+selector("getCurrentEpoch()"))
	if err != nil {
		return 0, err
	}
	if len(b) < 32 {
		return 0, errors.New("short answer")
	}
	return new(big.Int).SetBytes(b[:32]).Uint64(), nil
}

func decodeValidators(b []byte) (vals []RegVal, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("abi decode: %v", r)
		}
	}()
	word := func(off int) int { return int(new(big.Int).SetBytes(b[off : off+32]).Int64()) }
	arr := word(0)
	n := word(arr)
	base := arr + 32
	for j := 0; j < n; j++ {
		t := base + word(base+32*j)
		bo := t + word(t)
		addr := "0x" + hex.EncodeToString(b[t+32+12:t+64])
		l := word(bo)
		kb := b[bo+32 : bo+32+l]
		var p bls.G2Affine
		_, kerr := p.SetBytes(kb)
		rv := RegVal{Key: p, Hex: hex.EncodeToString(kb), Addr: addr, Valid: kerr == nil}
		// the other fixed fields follow the address inside the tuple head: activationEpoch, exitEpoch, status, isRetired
		if t+32*6 <= len(b) {
			rv.ActEp = uint64(word(t + 64))
			rv.ExitEp = uint64(word(t + 96))
			rv.Status = word(t + 128)
			rv.Retired = word(t+160) != 0
		}
		vals = append(vals, rv)
	}
	return vals, nil
}

func registryCommittee(url string, epoch uint64) ([]RegVal, error) {
	b, err := ethCall(url, "0x"+selector("getCommitteeValidators(uint32)")+fmt.Sprintf("%064x", epoch))
	if err != nil {
		return nil, err
	}
	return decodeValidators(b)
}

func registryValidators(url string, status int) ([]RegVal, error) {
	b, err := ethCall(url, "0x"+selector("getValidators(uint8)")+fmt.Sprintf("%064x", status))
	if err != nil {
		return nil, err
	}
	return decodeValidators(b)
}

// registrySnapshot prints who the registry lists right now: the committees it already knows for the
// current and the next epochs, and every unretired validator with its status.
func registrySnapshot(rpc string, eps map[uint64]*Epoch, regAddr map[string]string) {
	pf("\nConsensusRegistry %s (read-only, answers at the latest block):\n", registryAddr)
	ce, err := registryCurrentEpoch(rpc)
	if err != nil {
		pf("  getCurrentEpoch error: %v\n", err)
		return
	}
	pf("  getCurrentEpoch() = %d\n", ce)
	base := map[string]bool{}
	for _, e := range []uint64{ce - 1, ce, ce + 1, ce + 2} {
		reg, err := registryCommittee(rpc, e)
		if err != nil {
			pf("  getCommitteeValidators(%d): %v\n", e, err)
			continue
		}
		if e == ce {
			for _, r := range reg {
				base[r.Addr] = true
			}
		}
		var keys []string
		src := ""
		if ep, ok := eps[e]; ok {
			keys, src = ep.Rec.Committee, fmt.Sprintf("record %d committee", e)
		} else if ep, ok := eps[e-1]; ok {
			keys, src = ep.Rec.NextCommittee, fmt.Sprintf("record %d next_committee", e-1)
		}
		line := fmt.Sprintf("  getCommitteeValidators(%d): %d validators", e, len(reg))
		if src != "" {
			m, hit := matchCommittee(keys, reg)
			for k, v := range m {
				regAddr[k] = v
			}
			line += fmt.Sprintf(", %d of %d keys equal to %s", hit, len(keys), src)
		}
		pf("%s\n", line)
		if e > ce {
			for _, r := range reg {
				if !base[r.Addr] {
					pf("      not in the committee of epoch %d: %s\n", ce, r.Addr)
				}
			}
		}
	}
	all, err := registryValidators(rpc, 6)
	if err != nil {
		pf("  getValidators(Any): %v\n", err)
		return
	}
	count := map[string]int{}
	for _, v := range all {
		count[statusNames[v.Status]]++
	}
	pf("  all unretired validators, %d listed:\n", len(all))
	for _, v := range all {
		exit := ""
		if v.ExitEp != 0 {
			exit = fmt.Sprintf(", exit epoch %d", v.ExitEp)
		}
		act := fmt.Sprintf("%d", v.ActEp)
		if v.ActEp == 4294967295 {
			act = "not set yet"
		}
		pf("      %s  %-17s activation epoch %s%s\n", v.Addr, statusNames[v.Status], act, exit)
	}
}

// matchCommittee returns, for every record key, the registry address holding the same BLS point.
func matchCommittee(keys []string, reg []RegVal) (map[string]string, int) {
	m := map[string]string{}
	hit := 0
	for _, k := range keys {
		p, err := parsePK(k)
		if err != nil {
			continue
		}
		for _, r := range reg {
			if r.Valid && p.Equal(&r.Key) {
				m[k] = r.Addr
				hit++
				break
			}
		}
	}
	return m, hit
}

// ---------- negative tests on real data ----------

func roaringBytes(vals []int) []byte {
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

func b58encode(b []byte) string {
	n := new(big.Int).SetBytes(b)
	base := big.NewInt(58)
	mod := new(big.Int)
	var o []byte
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		o = append(o, b58alpha[mod.Int64()])
	}
	for _, c := range b {
		if c != 0 {
			break
		}
		o = append(o, '1')
	}
	for i, j := 0, len(o)-1; i < j; i, j = i+1, j-1 {
		o[i], o[j] = o[j], o[i]
	}
	return string(o)
}

func tamperTests(ep, prev *Epoch) {
	if ep == nil || prev == nil {
		pf("tamper tests skipped (need two consecutive records)\n")
		return
	}
	idx, _ := signerIdx(ep.Cert)
	pf("tamper tests on epoch %d (each one MUST fail):\n", ep.Rec.Epoch)
	pf("  untouched record + certificate        -> %s / digest %s\n", firstWord(checkSig(ep.Rec, ep.Cert, idx)), firstWord(checkDigest(ep.Rec, ep.Cert)))

	c1 := ep.Cert
	c1.Signature = prev.Cert.Signature
	pf("  %-38s-> %s\n", fmt.Sprintf("signature swapped from epoch %d", prev.Rec.Epoch), firstWord(checkSig(ep.Rec, c1, idx)))

	if len(idx) > 1 {
		fewer := idx[1:]
		c2 := ep.Cert
		c2.SignedAuthorities = b58encode(roaringBytes(fewer))
		res := "BELOW-QUORUM"
		if len(fewer) >= len(ep.Rec.Committee)*2/3+1 {
			res = firstWord(checkSig(ep.Rec, c2, fewer))
		}
		pf("  one signer removed from the bitmap    -> %s\n", res)
	}

	r3 := ep.Rec
	r3.ParentState.Number++
	pf("  checkpoint block number changed by +1 -> digest %s\n", firstWord(checkDigest(r3, ep.Cert)))
}

// ---------- main ----------

func utc(t int64) string {
	if t == 0 {
		return "-"
	}
	return time.Unix(t, 0).UTC().Format("2006-01-02 15:04:05")
}

func main() {
	rpc := flag.String("rpc", "https://mainnet-rpc.rayls.com", "JSON-RPC endpoint")
	explorer := flag.String("explorer", "https://explorer.rayls.com", "Blockscout explorer base URL (empty to skip)")
	from := flag.Uint64("from", 0, "first epoch")
	to := flag.Uint64("to", 0, "last epoch (0 = up to the newest record)")
	dir := flag.String("out", "data", "folder for saved raw answers")
	report := flag.String("report", "", "also write everything to this file")
	offline := flag.Bool("offline", false, "use only saved answers")
	show := flag.Int64("show", -1, "print one epoch in detail (default: the newest record)")
	registryOnly := flag.Bool("registry", false, "only print what the ConsensusRegistry lists right now (fast)")
	split := flag.Int64("split", -1, "also compare signer counts before and after this epoch")
	flag.Parse()
	_ = os.MkdirAll(*dir, 0o755)
	if *report != "" {
		if f, err := os.Create(*report); err == nil {
			defer f.Close()
			out = io.MultiWriter(os.Stdout, f)
		}
	}

	pf("Epoch handover check, read-only\n")
	pf("RPC      %s\nexplorer %s\n", *rpc, *explorer)
	pf("started %s UTC\n\n", time.Now().UTC().Format("2006-01-02 15:04:05"))

	last := *to
	if !*offline {
		if raw, err := rpcCall(*rpc, "rayls_nodeStatus", []any{}); err == nil {
			pf("node status: %s\n", string(raw))
			var st struct {
				Epoch uint64 `json:"epoch"`
			}
			_ = json.Unmarshal(raw, &st)
			if last == 0 {
				last = st.Epoch
			}
		} else {
			pf("node status error: %v\n", err)
		}
		if raw, err := rpcCall(*rpc, "eth_blockNumber", []any{}); err == nil {
			var h string
			_ = json.Unmarshal(raw, &h)
			n, _ := strconv.ParseUint(strings.TrimPrefix(h, "0x"), 16, 64)
			pf("latest block: %d\n\n", n)
		}
	}
	if *registryOnly {
		if *offline {
			pf("registry mode needs the live node\n")
			return
		}
		registrySnapshot(*rpc, map[uint64]*Epoch{}, map[string]string{})
		pf("\nfinished %s UTC\n", time.Now().UTC().Format("2006-01-02 15:04:05"))
		return
	}
	if last == 0 {
		last = 100000
	}

	pf("%-5s %-6s %-7s %-6s %-5s %-9s %-11s %-11s %s\n", "epoch", "signed", "bls", "hash", "chain", "committee", "block@rpc", "block@expl", "epoch closed (UTC)")
	var rows []Row
	eps := map[uint64]*Epoch{}
	var prev *Epoch
	part := map[string]int{}
	for e := *from; e <= last; e++ {
		cur, err := loadEpoch(*rpc, *dir, e, *offline)
		if errors.Is(err, errNotFound) {
			if e == *from {
				pf("%-5d no record\n", e)
				continue
			}
			pf("%-5d no record yet (epoch still running), stopping\n", e)
			break
		}
		if err != nil {
			pf("%-5d error: %v\n", e, err)
			prev = nil
			continue
		}
		eps[e] = cur
		var p *Epoch
		if prev != nil && prev.Rec.Epoch+1 == cur.Rec.Epoch {
			p = prev
		}
		r := analyse(cur, p)
		cp := cur.Rec.ParentState
		rb := rpcBlock(*rpc, *dir, cp.Number, *offline)
		r.RPCBlock = cmpBlock(cp.Hash, rb)
		r.Closed = rb.Time
		r.ExpBlock = "skip"
		if *explorer != "" {
			xb := explorerBlock(*explorer, *dir, cp.Number, *offline)
			r.ExpBlock = cmpBlock(cp.Hash, xb)
			if r.Closed == 0 {
				r.Closed = xb.Time
			}
		}
		rows = append(rows, r)
		for _, i := range r.Idx {
			if i < len(cur.Rec.Committee) {
				part[cur.Rec.Committee[i]]++
			}
		}
		comm := "-"
		if p != nil {
			comm = "same"
			if r.Changed {
				comm = "CHANGED"
			}
			if r.Continuity == "BREAK" {
				comm = "MISMATCH"
			}
		}
		if r.Err != "" {
			pf("%-5d error: %s\n", r.Epoch, r.Err)
		} else {
			pf("%-5d %d of %-3d %-7s %-6s %-5s %-9s %-11s %-11s %s\n", r.Epoch, r.K, r.N, firstWord(r.Sig), firstWord(r.Digest), r.Chain, comm, r.RPCBlock, r.ExpBlock, utc(r.Closed))
		}
		prev = cur
	}
	if len(rows) == 0 {
		pf("no records\n")
		return
	}
	lastEp := eps[rows[len(rows)-1].Epoch]

	// ---- summary ----
	var n, sigOK, digOK, chainBad, contBad, changed, rpcSame, expSame, expNA, atQuorum int
	minK := 1 << 30
	sigV, digV := map[string]int{}, map[string]int{}
	var closes []int64
	for _, r := range rows {
		if r.Err != "" {
			continue
		}
		n++
		if strings.HasPrefix(r.Sig, "VALID") {
			sigOK++
			sigV[r.Sig]++
		}
		if strings.HasPrefix(r.Digest, "MATCH") {
			digOK++
			digV[r.Digest]++
		}
		if r.Chain == "BREAK" {
			chainBad++
		}
		if r.Continuity == "BREAK" {
			contBad++
		}
		if r.Changed {
			changed++
		}
		if r.RPCBlock == "same" {
			rpcSame++
		}
		switch r.ExpBlock {
		case "same":
			expSame++
		case "n/a", "skip":
			expNA++
		}
		if r.K == r.Quor {
			atQuorum++
		}
		if r.K < minK {
			minK = r.K
		}
		if r.Closed > 0 {
			closes = append(closes, r.Closed)
		}
	}
	pf("\n---- summary (%d records, epochs %d to %d) ----\n", n, rows[0].Epoch, rows[len(rows)-1].Epoch)
	pf("aggregate BLS signature verified      : %d of %d\n", sigOK, n)
	for k, v := range sigV {
		pf("    %s x%d\n", k, v)
	}
	pf("record hash recomputed (blake3)       : %d of %d\n", digOK, n)
	for k, v := range digV {
		pf("    %s x%d\n", k, v)
	}
	pf("parent_hash chain breaks              : %d\n", chainBad)
	pf("committee differs from announced next : %d\n", contBad)
	pf("epochs where the committee changed    : %d\n", changed)
	pf("checkpoint block hash = RPC block     : %d of %d\n", rpcSame, n)
	pf("checkpoint block hash = explorer block: %d of %d (not reachable: %d)\n", expSame, n, expNA)
	pf("signers: fewest %d, exactly at quorum in %d of %d records\n", minK, atQuorum, n)
	step := 42
	for a := 0; a < len(rows); a += step {
		b := a + step
		if b > len(rows) {
			b = len(rows)
		}
		sum, q := 0, 0
		for _, r := range rows[a:b] {
			sum += r.K
			if r.K == r.Quor {
				q++
			}
		}
		pf("    epochs %3d-%3d: average %.2f signers, %2d of %d at exactly quorum\n", rows[a].Epoch, rows[b-1].Epoch, float64(sum)/float64(b-a), q, b-a)
	}
	if *split >= 0 {
		for _, part := range []struct {
			name   string
			lo, hi uint64
		}{{"before", 0, uint64(*split) - 1}, {"from", uint64(*split), ^uint64(0)}} {
			sum, q, c, all := 0, 0, 0, 0
			for _, r := range rows {
				if r.Err != "" || r.Epoch < part.lo || r.Epoch > part.hi {
					continue
				}
				c++
				sum += r.K
				if r.K == r.Quor {
					q++
				}
				if r.K == r.N {
					all++
				}
			}
			if c > 0 {
				pf("    %s epoch %d: %d records, average %.2f signers, %d at exactly quorum (%.0f%%), %d with all signers\n", part.name, *split, c, float64(sum)/float64(c), q, 100*float64(q)/float64(c), all)
			}
		}
	}
	if len(closes) > 2 {
		var gaps []float64
		for i := 1; i < len(closes); i++ {
			gaps = append(gaps, float64(closes[i]-closes[i-1])/3600)
		}
		sort.Float64s(gaps)
		pf("hours between epoch closes            : min %.2f, median %.2f, max %.2f\n", gaps[0], gaps[len(gaps)/2], gaps[len(gaps)-1])
	}

	// ---- registry ----
	regAddr := map[string]string{}
	if !*offline {
		registrySnapshot(*rpc, eps, regAddr)
	}

	// ---- digest naming: blake3 (code) vs keccak256 (RPC doc) ----
	if lastEp != nil && !*offline {
		pf("\nWhich hash does the node use for rayls_epochRecordByHash? (epoch %d)\n", lastEp.Rec.Epoch)
		enc, _ := bcsRecord(lastEp.Rec, 4, true, true)
		b3 := blake3Sum(enc)
		kk := keccak256(enc)
		for _, h := range []struct{ name, hex string }{{"blake3   ", "0x" + hex.EncodeToString(b3[:])}, {"keccak256", "0x" + hex.EncodeToString(kk[:])}} {
			raw, err := rpcCall(*rpc, "rayls_epochRecordByHash", []any{h.hex})
			res := ""
			switch {
			case errors.Is(err, errNotFound):
				res = "not found"
			case err != nil:
				res = "error: " + err.Error()
			default:
				var pair []json.RawMessage
				var rec Record
				if json.Unmarshal(raw, &pair) == nil && len(pair) == 2 && json.Unmarshal(pair[0], &rec) == nil {
					res = fmt.Sprintf("found epoch %d", rec.Epoch)
				} else {
					res = "unexpected answer"
				}
			}
			pf("  %s %s -> %s\n", h.name, h.hex, res)
		}
	}

	// ---- negative tests ----
	pf("\n")
	var t1, t0 *Epoch
	for e := lastEp.Rec.Epoch; e > 0; e-- {
		if ep, ok := eps[e]; ok {
			if idx, _ := signerIdx(ep.Cert); len(idx) == len(ep.Rec.Committee) {
				if pe, ok := eps[e-1]; ok {
					t1, t0 = ep, pe
					break
				}
			}
		}
	}
	tamperTests(t1, t0)

	// ---- one epoch in detail, to compare with the explorer by eye ----
	var d *Epoch
	if *show >= 0 {
		d = eps[uint64(*show)]
	} else {
		d = lastEp
	}
	if d != nil {
		idx, _ := signerIdx(d.Cert)
		pf("\nepoch %d in detail:\n", d.Rec.Epoch)
		pf("  committee (%d keys, quorum %d):\n", len(d.Rec.Committee), len(d.Rec.Committee)*2/3+1)
		signed := map[int]bool{}
		for _, i := range idx {
			signed[i] = true
		}
		for i, k := range d.Rec.Committee {
			mark := "did not sign"
			if signed[i] {
				mark = "signed"
			}
			pf("    [%d] %s...  %s\n", i, short(k), mark)
		}
		pf("  checkpoint block : %d\n", d.Rec.ParentState.Number)
		pf("  checkpoint hash  : %s\n", d.Rec.ParentState.Hash)
		pf("  record hash      : %s\n", d.Cert.EpochHash)
		pf("  signature        : %s...\n", short(d.Cert.Signature))
		if *explorer != "" {
			pf("  compare with     : %s/block/%d\n", strings.TrimRight(*explorer, "/"), d.Rec.ParentState.Number)
		}
	}

	// ---- participation ----
	pf("\nsignatures per validator key (address from the registry where matched):\n")
	type kv struct {
		k string
		v int
	}
	var kvs []kv
	for k, v := range part {
		kvs = append(kvs, kv{k, v})
	}
	sort.Slice(kvs, func(i, j int) bool { return kvs[i].v > kvs[j].v })
	for _, x := range kvs {
		a := regAddr[x.k]
		if a == "" {
			a = "-"
		}
		pf("  %s  %s  %d of %d records\n", short(x.k), a, x.v, n)
	}

	// ---- csv ----
	if f, err := os.Create(filepath.Join(*dir, "epochs.csv")); err == nil {
		fmt.Fprintln(f, "epoch,signers,committee_size,quorum,signer_indexes,bls,hash,chain,committee_changed,checkpoint_block,block_rpc,block_explorer,closed_utc")
		for _, r := range rows {
			ix := make([]string, len(r.Idx))
			for i, v := range r.Idx {
				ix[i] = strconv.Itoa(v)
			}
			cpb := uint64(0)
			if ep, ok := eps[r.Epoch]; ok {
				cpb = ep.Rec.ParentState.Number
			}
			fmt.Fprintf(f, "%d,%d,%d,%d,%s,%s,%s,%s,%v,%d,%s,%s,%s\n", r.Epoch, r.K, r.N, r.Quor, strings.Join(ix, " "), firstWord(r.Sig), firstWord(r.Digest), r.Chain, r.Changed, cpb, r.RPCBlock, r.ExpBlock, utc(r.Closed))
		}
		f.Close()
	}
	pf("\nfinished %s UTC\n", time.Now().UTC().Format("2006-01-02 15:04:05"))
}
