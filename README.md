# track-record

Append-only record. One entry per weekday, committed before the New York open; the pick is sealed
(only its sha256 is published) and revealed at 11:30 New York. Every entry is signed with the key in
`entries/000000.json` and logged in Sigstore Rekor.

```
entries/NNNNNN.json        entry (canonical JSON, prev = sha256 of previous entry file)
entries/NNNNNN.json.ots    OpenTimestamps proof (Bitcoin)
proofs/                    Rekor inclusion proofs, checkpoints, RFC 3161 tokens
reveals/NNNNNN.json        sealed pick, published at 11:30 (sha256 = commitment)
tsa-certs/                 FreeTSA root CA (others: system CA store)
```

## Verify
```
pip install py_ecc
python3 verify.py              # chain, signatures, Rekor proofs, timestamps, deadlines, reveals
python3 verify.py --days 3     # + scan Rekor for any other entry signed with the ledger key
pip install opentimestamps-client
python3 verify.py --ots        # + Bitcoin anchors
```

Git commit metadata is not evidence; the signatures, Rekor proofs and timestamp tokens are.
