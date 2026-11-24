# Local model selection: Llama 3.1

Model: `ollama:llama3.1:8b`. Source commit for the hook and candidate policy:
`0250e85f9882f26a35535525f471e9b0a8de8f4f`.

One benign dcode smoke run completed with exit 0. It issued two hooked calls:
Write and Bash, both allowed. The inert marker matched; both signed receipts
carried the candidate policy hash. Signatures and hash chain checked: pass.
The local anchor check passed; no Merkle checkpoints were emitted below the
configured interval. There were no hook timeout warnings.

The exact pins, package versions, parameters and aggregate observations are in
[v1_5-local-model-smoke.json](v1_5-local-model-smoke.json). Its 77.36-second elapsed
value measures the entire dcode subprocess, including startup and inference; it
is not hook latency or an overhead benchmark. The harness retry limit was 3,
with a 4-turn and 300-second bound. No attack case or scored run was executed.

## Provenance and check corrections

`ollama list` reports short ID `46e0c10c039e`; the active daemon's full digest is
`sha256:46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e`.
The reported digest was unchanged after the run.

The default local manifest file's byte hash differs from that daemon-reported
digest. The cause is unresolved; neither hash is substituted for the other.
Both are retained. The model weights bytes hash to the layer digest referenced
by the daemon modelfile and the local manifest. Future pin checks should compare
the active daemon digest, weights digest and local manifest byte hash separately.
A metadata precheck halted before inference when it assumed the manifest file's
hash must equal the API digest; that assumption was removed and the discrepancy
recorded, with a weights-byte hash check added.

The initial signature check selected a different generated temporary key. The
hook used the signer under its temporary HOME/.receiptd, not the requested
separate temporary keys directory. Checking with the actual signer's public key
passed. The ledger byte hash stayed unchanged; the model was not run again.
Future runners must establish the actual hook signer rather than assume its key
directory from the parent process environment.

## Scope and next inputs

This was a benign dcode harness check with an isolated temporary HOME, workspace,
fixture keys and environment without hosted credentials. MCP loading, the JS
interpreter and tracing were disabled. It was not a VM/Seatbelt run, a live
Claude Code smoke, or evidence of general tool-calling reliability. Raw output,
receipts and synthetic session files remain private; only aggregates are committed.

The backup model was not pulled. The unused qwen2.5:0.5b local copy was removed;
qwen2.5:7b remains installed for continuity.

Phase 4 has not started. Nick still supplies the hand-authored held-out prompts
and real private git-config benign session. Assistant-authored cases would be
policy-exposed and cannot be described as independent of policy development.
