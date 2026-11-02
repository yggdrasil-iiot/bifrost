# Command proposal

A command proposal is how an AI agent asks for one OPC UA Method call on the plant through Bifrost's governed write path. The agent signs it; a different, named approver co-signs it with `gates command approve`. Design: yggdrasil-iiot/vor `docs/superpowers/specs/2026-11-02-vor-m2-governed-write-design.md`. Code: `core/src/main/java/dev/krillin/bifrost/core/command/CommandProposal.java` and the CLI `gates command`. The agent-side signer `vor-propose` lives in the vor repository. Delivering an approved envelope to an edge and executing it in Heimdall are later steps of the same design; Heimdall repeats the checks at execution time.

## Envelope

DSSE v1.0.2 envelope, `payloadType` `application/vnd.in-toto+json`, payload is an in-toto Statement v1.

Every signature is Ed25519 over PAE(payloadType, payload). `keyid` names the principal and is only a hint; a signature counts for a principal only when it verifies under a key registered for that principal in `identity/authorized-keys.jsonl`.

A proposal carries exactly one signature, the proposer's. An approved envelope carries exactly two: the proposer's signature, unchanged, followed by the approver's, both over the same PAE bytes. Approval never re-serializes the payload: the `payload` string is copied as it is. Two signatures that resolve to the same public key count as one person (`identity.four-eyes.same-key`), even under two principal names.

## Statement

Exactly four top-level fields: `_type` = `https://in-toto.io/Statement/v1`, `subject`, `predicateType` = `https://github.com/yggdrasil-iiot/bifrost/attestation/command-proposal/v1`, `predicate`.

`subject` is exactly three entries in this order, each `{name, digest: {sha256}}` with a lowercase hex SHA-256 over raw bytes:
1. `heads/<streamId>.json` - the stream head file in the registry (`mappings/heads/<streamId>.json`).
2. `releases/<release id>/<version>/release.json` - the release the head names.
3. `evidence` - the decoded evidence bytes.

`predicate` has exactly eight fields:
- `cmdId`: lowercase RFC 4122 UUID.
- `streamId`: the mapping stream, characters `[a-zA-Z0-9._-]`.
- `target`: `{group, edge, device}`, all non-empty strings; the Sparkplug coordinates the command policy matches.
- `method`: `{objectNodeId, methodNodeId, inputs}`. Both NodeIds are expanded NodeIds of the form `nsu=<namespace URI>;s=<identifier>`, never a namespace index; for the sim, `nsu=urn:bifrost:opcua:sim;s=Line1/Mixer1` and `nsu=urn:bifrost:opcua:sim;s=Line1/Mixer1.SetTemperature`. `inputs` holds exactly one `{name, type, value}` with `type` `Double` and a finite JSON number as `value`.
- `validity`: `{notBefore, notAfter}`, UTC to the second (`YYYY-MM-DDTHH:MM:SSZ`), `notBefore` before `notAfter`, span at most 900 seconds (15 minutes).
- `proposedBy`: the agent principal.
- `approvedBy`: the one principal allowed to co-sign; must differ from `proposedBy`.
- `evidence`: `{mediaType: "application/json", base64}`. The decoded bytes are the JSON answer of Vor's `read_governed` call, carried byte for byte; its SHA-256 is the `evidence` subject. Approval reads `verdict.usable` (must be `true`) and `answer.pin` (`stream_id`, `release_id`, `version`, `release_sha256`), which must name the predicate's stream and the current head's release id, version and SHA-256.

## Grants

In `identity/activation-policy.json`, the same file and rule shape as the other activation grants. The agent needs action `propose_command` and the approver `approve_command`, each on target `command`, kind `method`, ref = the `streamId`.

`activate` and `approve` grants on the same resource do not stand in for them.

Grants are Bifrost policy, read from the registry; nothing in the proposal asserts them.

## Command policy

Approval checks the call against a command policy file passed with `--policy`, in the same format as Heimdall's `policy.json` (`version`, `rules`, `default`), evaluated by the same `CommandAuthorizer`: first match, deny by default, and `default` must be `deny`.

The request it evaluates: `target` from the predicate, command = the `methodNodeId` string, value = the input value, type `Double`, subject = `proposedBy`. A rule's `constraint` (`type`, `min`, `max`, inclusive) bounds the value, and its `principal` must be the proposer.

## gates command approve

Usage: `gates command approve <registry> <proposal> --approved-by <id> --approved-by-key <path> --policy <command-policy.json> --out <path>`

Checks, in order; the first failure refuses with its reason code, exits 1 and writes nothing:
1. The envelope has exactly one signature.
2. The statement's shape: field sets, formats, `proposedBy` differs from `approvedBy`, the window span, and the evidence bytes match the `evidence` subject.
3. The proposer's signature verifies under a registered key of `proposedBy`.
4. `--approved-by` equals `approvedBy`.
5. The current time is before `notAfter`. Approval may come before `notBefore`.
6. `proposedBy` holds `propose_command` and the approver holds `approve_command` on the stream.
7. The stream head passes the same check as `gates mapping verify-head` (signed head attestation, not expired); its `mapping.head-*` reason codes pass through unchanged. Then the head file bytes, the release path and the `release.json` bytes must match subjects 1 and 2.
8. The evidence parses, its verdict is usable, and its pin names this stream and this head's release.
9. The command policy admits the call.
10. The approver's key file matches a key registered for the approver and is inside its validity window.

Then the approver signs the PAE bytes, the two-signature envelope is verified again, and it is written to `--out`, which must not exist yet (`command.out-exists`). The JSON report (`kind` `command-approval`) names `cmdId`, the target, method, value, window, both principals, the head, and the ids of the two grant rules and the policy rule (`proposeGrant`, `approveGrant`, `policyRule`), with `execution` `excluded`.

## gates command verify

Usage: `gates command verify <registry> <envelope> [--approved]`

Without `--approved` it expects a proposal (exactly one signature, the proposer's); with it, an approved envelope (exactly two, the proposer's and the approver's, on distinct keys).

It runs checks 2, 3, 7 and 8 above (with both signatures when `--approved`). It does not check grants, the command policy or the current time against the window; the head's own expiry is checked.

Report `kind`: `command-proposal-verification` or `command-approved-verification`.

Exit codes for both subcommands: 0 accepted, 1 refused with a JSON `command-refusal` carrying `error`, 2 usage.

## Reason codes

- `command.malformed` - not a statement of this shape, a bad base64 field, or evidence that does not parse.
- `command.signature` - wrong signature count, a signature that does not verify (a changed byte or a re-serialized payload included), or an approver key that is not registered or outside its window.
- `identity.four-eyes.same-key` - `proposedBy` equals `approvedBy`, or both signatures resolve to one key.
- `command.approver.mismatch` - the approving principal is not `approvedBy`.
- `command.window` - span over 15 minutes, `notBefore` not before `notAfter`, or the proposal has expired.
- `command.grant` - a missing `propose_command` or `approve_command` grant.
- `command.head.mismatch` - the subjects or the evidence pin do not name the head and release this registry serves now.
- `command.evidence.digest` - the evidence bytes do not match the `evidence` subject.
- `command.evidence.unusable` - the evidence verdict is not usable.
- `command.policy.denied` - the command policy refuses the call, or its default is not `deny`.
- `command.out-exists` - the `--out` file already exists.
