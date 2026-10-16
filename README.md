# Who signs the daily handover on the Rayls Public Chain

Read-only check of every `rayls_epochRecord` handover record on Rayls Public Chain mainnet (chainId 72957), run on 16 October 2026. All times UTC.

## What the checker does

For each epoch record it asks the public RPC (`https://mainnet-rpc.rayls.com`) for `rayls_epochRecord(n)`, saves the raw answer, and then:

1. Rebuilds the record hash: blake3 over the BCS encoding of the record, and compares it with `epoch_hash` in the certificate.
2. Verifies the aggregate BLS12-381 signature (min-sig: 48-byte signature in G1, 96-byte keys in G2, DST `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_`) over the intent message `01 00 01 20 || epoch_hash`, using only the committee keys marked in `signed_authorities` (portable RoaringBitmap).
3. Checks that `parent_hash` equals the previous record's hash, and that the committee equals the previous record's `next_committee`.
4. Compares the checkpoint block (`parent_state`) with `eth_getBlockByNumber` on the RPC and with the Blockscout API on explorer.rayls.com.
5. Reads the ConsensusRegistry (`0x07e17e17e17e17e17e17e17e17e17e17e17e17e1`) and matches its committee keys to the record keys.
6. Asks `rayls_epochRecordByHash` with the blake3 hash and with the keccak256 hash of the same record.
7. Runs three tamper tests on a real record (signature from another epoch, one signer removed, checkpoint block number +1). Each must fail.

The quorum used is the one in `epoch.rs`: `floor(2n/3)+1`, so 5 of 7.

## Results

- 170 of 170 records (epochs 0 to 169) verify: hash, signature, chain, committee continuity, checkpoint block on RPC and explorer.
- The 7 committee keys equal the ConsensusRegistry keys.
- `rayls_epochRecordByHash` finds record 169 by its blake3 hash and finds nothing by its keccak256 hash, although `doc/crates/execution/rpc.md` line 127 says keccak256.
- Records with exactly 5 of 7 signatures: 17 of 134 up to 10 Sep (13%), 21 of 36 from 11 Sep (58%). Per validator: 131 to 163 signatures out of 170.
- Validator `0xbbd0b35294fff3981a7aeb2adb14f23f93bf9662`: allowlisted 15 Oct 15:28:24, staked 5,000,000 RLS 16 Oct 06:40:16, activate 06:41:05. `PendingActivation` at 09:17 (registry-20261016-0917-UTC.txt), `Active` after the 15:58:56 handover, and `getCommitteeValidators(172)` returns 8 (registry-20261016-1649-UTC.txt).
- With 8 validators the same formula gives 6, and a handover can still lose only 2 validators.

## Not verified

- All data came through one public RPC node (role: observer). The explorer is a second view of the same chain, not a second node.
- Why certificates carry fewer signatures since 11 September. The certificate is sealed at quorum (current code) or after a one-second lull (older code), so a missing signature does not by itself show an offline validator; a vote that arrives after the cut is also missing. Which version mainnet runs is not visible from outside.
- Records 0 to 168 were fetched at 06:36 to 06:39 UTC and record 169 at 16:50 UTC; the 16:50 run re-verified everything from the saved answers.

## Files

- `main.go`, `scan.go`, `blake3.go`, `keccak.go`, `main_test.go`, `go.mod`, `go.sum`: the checker (Go, gnark-crypto for BLS12-381; blake3 and keccak256 written from the specs and tested against official vectors).
- `run.ps1`: full check. `registry.ps1`: registry snapshot only.
- `report-2026-10-16-1650-UTC.txt`: full output of the final run.
- `registry-20261016-0917-UTC.txt`, `registry-20261016-1649-UTC.txt`: registry before and after the 16 Oct handover.
- `epochs.csv`: one row per record.
- `epoch_records_raw.jsonl`: the raw `rayls_epochRecord` answer for every epoch, 0 to 169.

Run: `go run . -out data -report report.txt -split 134` (full check) or `go run . -registry` (registry only). Offline re-check: write each line of `epoch_records_raw.jsonl` to `data/epoch_NNNN.json` (the `rayls_epochRecord` value only), then `go run . -offline -explorer "" -out data`.
