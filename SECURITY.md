# Security policy

## What this project is

Bifrost is a **systems-architecture reference implementation**, not a supported product. It is
not distributed as a binary, not published to a package registry, and nobody is running it in a
plant. That framing matters for what follows: this policy describes how a security report is
handled here, and it is not a commercial support commitment or a CE-marked manufacturer's
vulnerability-handling process under the EU Cyber Resilience Act.

If that changes — if this is ever placed on a market — this file has to be replaced with a real
process, not amended. See [`docs/ENTERPRISE.md`](docs/ENTERPRISE.md) §7 for what is missing
between here and there.

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting**: the *Security* tab of this repository →
*Report a vulnerability*. That keeps the report private until there is something to say
publicly, and it does not require an email address from either side.

Please do not open a public issue for something exploitable.

**What helps.** The version or commit, which module (`core`, `gates`, `heimdall`, `sim`), and a
reproduction — ideally as a failing test or a gate script invocation, since every claim in this
repository is expected to be reproducible that way.

**What to expect.** This is maintained by one person. There is no on-call rotation and no SLA to
offer, so none is promised. The honest expectation is acknowledgement within a few days and a
fix or a documented decision after that. If a report goes unanswered for two weeks, escalating by
opening a public issue that says only "unacknowledged private report, see Security tab" is
reasonable and will not be treated as bad faith.

## Already known, and by design

Please check these before reporting. They are documented limitations, not undisclosed holes, and
each is stated in the README's *Honest scope & limitations* or in `docs/ENTERPRISE.md`:

- **The trust anchor is a plaintext registry file** (`authorized-keys.jsonl`). Key bootstrap and
  distribution are out of band. There is no PKI, OIDC or CRL.
- **The activation policy is plaintext** and unsigned; its change control is out of band.
- **The edge bars above signing are opt-in.** `REQUIRE_SIGNED_ACTIVATION` and
  `REQUIRE_ANCHORED_ACTIVATION` both default to `false`. Heimdall does not fail closed on an
  unsigned ledger unless you turn that on.
- **Anchor rollback resistance is topological, not cryptographic.** A `FileAnchorStore` is an
  on-box projection that a co-rollback can rewrite; the `GitAnchorStore` only helps if the anchor
  repository is genuinely off-box. The gate says so itself.
- **Authorization is direct principal grants**, not roles or attributes.
- **Rotation exists; revocation does not.** `identity rotate-key` retires a signing key by stamping
  `notAfter`, which stops it signing anything new. It goes on authenticating everything it already
  signed -- deliberately, because a ledger entry carries no key id and its timestamp is
  self-asserted, so there is no honest way to decide which key was valid when. **A report that a
  retired key still verifies its own history is not a finding**; a report that it can still sign
  something new is. Invalidating past signatures needs a trusted time source this project does not
  have. See `docs/ENTERPRISE.md` §10.
- **Certificate renewal is manual and self-signed.** `EdgeIdentity renew` mints a successor and
  keeps the predecessor; the thumbprint changes and must reach the server out of band. There is no
  CA, no GDS and no enrolment, and an **expired certificate does not stop the edge** -- it is
  diagnosed and announced, because failing closed on a lapsed transport credential would turn a
  missed renewal into a stopped line. That is a recorded decision, not an oversight. See §6.
- **Divergence findings and bypass findings are visibility, not enforcement.** `model-reconcile`
  and `conduit-project` produce findings with an owner; neither blocks anything.

A report that one of these is exploitable in a specific, non-obvious way is welcome — the point
is that "the keys are in a plaintext file" on its own is already written down.

## Out of scope

- The `sim` module. It is a test fixture: an embedded OPC-UA server with an instant
  setpoint-equals-process-value transfer, present so the gates have something to drive.
- Denial of service against a local demo, and anything that requires already having write access
  to the registry or the machine.
- Findings in third-party dependencies with no exploit path through this code. Those belong
  upstream. The dependency inventory is in the CycloneDX SBOM (`mvn package` →
  `target/bifrost-sbom.json`), and it is attached to releases.

## Supported versions

Pre-1.0. Only the latest tag and `main` are looked at.
