# R1 — Command Identity Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give a runtime command a requester, so that Heimdall's deny-by-default is an ACL over principals and not only an allowlist over metrics — and so `ENTERPRISE.md`'s definition of governance ("a record of who authorized what") is true on the command path, not only on the model-activation path.

**Architecture:** The design for this already exists in the repo and is disconnected at both ends. `Rule` carries a `principal`, `policy.json` populates it on every rule, `BrokerAclProjector` turns those into broker ACL entries — and `CommandAuthorizer` never reads the field while the projector is used by nothing but its own unit test. R1 connects both ends: the edge learns a subject from a **signed command envelope** it verifies itself, and the projection becomes a CLI that emits a real broker ACL.

**Tech Stack:** Java 17, Eclipse Tahu (Sparkplug B metric properties), `core/identity` Ed25519 primitives, JUnit 5.10.3, Docker (broker for the gate).

---

## Why this round exists

`ENTERPRISE.md` defines what the project means by governance:

> Governance here means one thing: **a declared boundary, enforced where traffic has to pass, with a record of who authorized what.**

On the model-activation path that is true — four-eyes, Ed25519, an anchored ledger. On the **command** path, the path that actually moves the plant, there is no *who* at all:

```java
public record CommandRequest(Target target, String command, Object value, String type) {}
public record Target(String group, String edge, String device) {}
```

```java
// CommandAuthorizer.authorize — r.principal() is never read
if (!targetMatches(r.target(), req.target())) continue;
if (!r.command().equals(req.command())) continue;
```

The intent was a split: the **broker** decides *who may publish*, the **edge** decides *what may be commanded*. `policy.json` carries `"principal": "recipe-writer"` on all three rules for exactly that, and `BrokerAclProjector` projects them to `principal → NCMD topic PUBLISH`. **Neither half is connected.** The edge ignores the field, and `grep` finds the projector used only by `BrokerAclProjectorTest`. The demo broker runs `HIVEMQ_ALLOW_ALL_CLIENTS=true`.

So the answer to "which operator issued this setpoint" is: unknown, and unknowable from the record.

**What this round does NOT claim** — carried into the docs in Chunk 5:

- It gives the command a **verified requester**. It does **not** add a tamper-evident record of commands; that is R2, and until it exists the subject appears in a log line and an MQTT response, nothing more.
- The subject is a **principal name bound to an Ed25519 key**, from the same plaintext `authorized-keys.jsonl` trust anchor the activation ladder uses. Key bootstrap, distribution and revocation stay out of band, exactly as `ENTERPRISE.md` §6 already says.
- Authorization stays **direct principal grants**, not roles or attributes. `ENTERPRISE.md` already says so and it stays true.

---

## Facts verified against the source on 2026-09-08

| Fact | Verified |
|---|---|
| `Rule` already has a principal | `core/.../acl/Rule.java` — `record Rule(String id, String principal, Target target, String command, Constraint constraint)` |
| `policy.json` populates it | `heimdall/registry/policy.json` — all three rules carry `"principal": "recipe-writer"` |
| `CommandAuthorizer` ignores it | `core/.../acl/CommandAuthorizer.java` — matches target, command, constraint; `r.principal()` appears nowhere |
| `BrokerAclProjector` is dead code | Referenced only by `BrokerAclProjectorTest`. Its own javadoc: *"produces a static artifact only — it does not enforce live RBAC on the broker"* |
| The signing primitives exist | `Ed25519Keys.sign(byte[], PrivateKey) -> String` (base64), `verify(byte[], String, PublicKey)`, `AuthorizedKeys.load(Path).forPrincipal(String) -> Optional<PublicKey>` |
| The house preimage idiom | `LedgerChain` — explicit ordered concatenation joined by `SEP = ''`, with a `NULL_SENTINEL`, **not JSON**, so writer and verifier cannot diverge. R1's envelope follows it |
| **There is no trust anchor in heimdall's registry** | `heimdall/registry/` holds `policy.json`, `conformance/`, `udt/` and **no `identity/`**. The gate must mint `authorized-keys.jsonl`, as the activation gates already do under `build/` |
| The demo broker allows everyone | `docker-compose.yml` — `HIVEMQ_ALLOW_ALL_CLIENTS: "true"`, with a comment saying HiveMQ CE otherwise refuses all connections |

### Decisions locked here

**(a) Principal matching is gated by the bar, not switched on globally.**
Every existing rule names `recipe-writer`, and every existing test and gate publishes with no subject at all. Making principal matching unconditional would fail 16 `CommandAuthorizerTest` cases and the runtime gate on day one. So: **`CommandAuthorizer` checks the principal only when the request carries a subject.** A null subject means "not asserted", and the rule's principal is advisory exactly as it is today.

That is fail-open *in isolation*, and it must not be read as the whole story: what makes the composition fail-closed is `REQUIRE_SIGNED_COMMAND`, which rejects an unsigned command **before** `authorize` is ever called. Write that reasoning into both javadocs, because the isolated method looks weaker than the system.

**(b) The subject comes from a signed envelope, not from the broker.**
MQTT does not tell a subscriber who published. The alternatives were broker-injected identity (vendor-specific) or a separate authenticated intake (a second protocol). A signed envelope is broker-neutral, verifiable by the edge itself, and reuses the Ed25519 machinery already trusted for activation. **The broker ACL is still worth projecting** — defence in depth, and it is half-built — but it cannot be the thing the record depends on.

**(c) Replay is in scope, because "signed" without it is a weaker claim than it sounds.**
A captured signed NCMD can be re-published verbatim. The envelope therefore binds the payload's `cmdId`, and the bridge keeps a bounded set of recently-seen `cmdId`s and refuses a repeat. This is a **window, not a proof**: an attacker who waits past the window can replay. Say so in the docs rather than implying freshness the design does not have — the durable fix is a timestamp plus a clock the site trusts, and OT sites frequently have neither.

---

## Chunk 1: A command has a subject

### Task 1: `CommandRequest` carries it; `CommandAuthorizer` matches it

**Files:**
- Modify: `core/src/main/java/dev/krillin/bifrost/core/acl/CommandRequest.java`, `CommandAuthorizer.java`
- Test: `core/src/test/java/dev/krillin/bifrost/core/acl/CommandAuthorizerTest.java`

- [ ] **Step 1: Write the failing tests**

```java
    @Test void subjectMatchingRulePrincipalIsAllowed() {
        Decision d = auth.authorize(policy, req("ns=2;s=Recipe/Rpm", 1500.0, "Double", "recipe-writer"));
        assertTrue(d.allowed(), d.reason());
    }

    @Test void subjectNotMatchingRulePrincipalIsDenied() {
        Decision d = auth.authorize(policy, req("ns=2;s=Recipe/Rpm", 1500.0, "Double", "someone-else"));
        assertFalse(d.allowed());
        assertTrue(d.reason().contains("principal"), d.reason());
    }

    /**
     * Backward compatibility, and it is load-bearing: every rule in policy.json names a principal
     * and every pre-R1 caller passes none. A null subject means "not asserted", and the check is
     * skipped — what makes the composition fail-closed is REQUIRE_SIGNED_COMMAND refusing an
     * unsigned command before this method is reached.
     */
    @Test void noSubjectMeansThePrincipalIsNotChecked() {
        assertTrue(auth.authorize(policy, req("ns=2;s=Recipe/Rpm", 1500.0, "Double", null)).allowed());
    }
```

- [ ] **Step 2: Run to verify red** — `mvn -q -pl core test -Dtest=CommandAuthorizerTest -Dsurefire.failIfNoSpecifiedTests=false`
- [ ] **Step 3: Implement**

`CommandRequest` gains `String subject` as the last component. **This breaks every direct construction** — expect them in `CommandAuthorizerTest`, `NcmdBridgePolicyTest` and `NcmdOpcUaBridge`. Add a 4-arg compact convenience constructor delegating with `subject = null` so only the new tests change.

In `CommandAuthorizer`, inside the rule loop after the command match:

```java
            // Principal is checked only when the caller asserted one. See the class javadoc: a null
            // subject is "not asserted", not "anonymous is fine" — REQUIRE_SIGNED_COMMAND is what
            // makes an unasserted subject impossible, and it does so before this method runs.
            if (req.subject() != null && !principalMatches(r.principal(), req.subject())) {
                return Decision.deny("principal-mismatch: rule '" + r.id() + "' is for " + r.principal());
            }
```

`principalMatches` treats a null or `"*"` rule principal as any, mirroring `fieldMatches`.

- [ ] **Step 4: Green, then the whole reactor** — `mvn -q test`
- [ ] **Step 5: Commit**

---

## Chunk 2: The envelope

### Task 2: `CommandEnvelope` — preimage and verification

**Files:**
- Create: `core/src/main/java/dev/krillin/bifrost/core/acl/CommandEnvelope.java`
- Test: `core/src/test/java/dev/krillin/bifrost/core/acl/CommandEnvelopeTest.java`

- [ ] **Step 1: Write the failing tests**

Cover: a good signature verifies; a tampered value does not; a tampered command does not; the wrong principal's key does not; an unknown principal does not; and **the preimage binds the cmdId**, so a signature for one command does not verify for another.

- [ ] **Step 2: Run to verify red**
- [ ] **Step 3: Implement**

```java
    private static final char SEP = '';   // same as LedgerChain: cannot occur in field values

    /** Ordered, delimiter-joined, NOT JSON — so signer and verifier cannot diverge on encoding. */
    public static String preimage(String group, String edge, String cmdId,
                                  String command, String value, String type) { … }
```

plus `sign(...)` and `verify(AuthorizedKeys, subject, sig, …)`. Follow `LedgerChain`'s `NULL_SENTINEL` treatment for null fields.

- [ ] **Step 4: Green**
- [ ] **Step 5: Commit**

### Task 3: The bridge verifies it, behind a bar

**Files:**
- Modify: `heimdall/.../NcmdOpcUaBridge.java`, `NcmdOpcUaBridgeMain.java`
- Test: `heimdall/.../NcmdOpcUaBridgeTest.java`

`REQUIRE_SIGNED_COMMAND` (env, default OFF) via the existing `flag(...)` helper. When ON:

- a command with no `sub`/`sig` property is refused with `command.unsigned`
- a bad signature is refused with `command.sig.invalid`
- an unknown principal is refused with `command.principal.unknown`
- a repeated `cmdId` is refused with `command.replay`
- otherwise the verified subject goes into `CommandRequest`

When OFF, `handle(...)` behaves exactly as today — subject null, no verification — which is what keeps the six existing gates meaningful.

**Replay guard:** a bounded `LinkedHashMap` LRU of recent `cmdId`s (size from `HEIMDALL_REPLAY_WINDOW`, default 1024), consulted only when the bar is on. Its javadoc must say plainly that this is a window and not a proof.

- [ ] **Step 1: failing tests** (one per reason code, plus a replay test, plus "bar off ⇒ unchanged")
- [ ] **Step 2: red · Step 3: implement · Step 4: green · Step 5: whole suite · Step 6: commit**

### Task 4: A signing publisher for the gate

**Files:**
- Modify: `heimdall/.../RogueNcmd.java` (optional `--sign <principal> <keyfile>`), or create `SignedNcmd.java`

Prefer extending `RogueNcmd` with optional flags over a second near-copy: the gates already use it everywhere, and two publishers that differ by one property will drift.

- [ ] **Step 1: implement · Step 2: verify by hand against a live broker · Step 3: commit**

---

## Chunk 3: The broker half

### Task 5: `acl-project` CLI

**Files:**
- Create: `gates/src/main/java/dev/krillin/bifrost/gates/AclProjectGate.java` (or extend the existing gates CLI)

Emit the projection as a real file. **Check the surrounding CLI's conventions first** — the `gates` jar already has a command dispatch pattern; follow it rather than adding a second entry point.

**RISK, to resolve before writing the gate leg in Task 6.** HiveMQ CE enforces nothing without an extension, and the compose file runs the *allow-all* extension deliberately. Enforcing a projected ACL needs the file-RBAC extension, which may not be obtainable offline. **Verify this early.** If it is not available, say so in the docs and land the projection as a *verified artifact* — CLI output plus a unit test — rather than inventing a broker leg that does not run. That is still strictly better than today, where the projector has no caller at all; it is not a claim that the broker enforces anything.

- [ ] **Step 1: verify extension availability · Step 2: implement · Step 3: test · Step 4: commit**

---

## Chunk 4: Evidence

### Task 6: `run-command-identity-gate.sh`

Reuse the R0/R3 gate idiom: `cygpath` shim, `fail`, `kill_by_jvmarg`, count-based assertions, and **never grep an accumulating log without a baseline**.

| | Asserts |
|---|---|
| **C1** | A correctly signed command from `recipe-writer` is applied (APPLY count **increase**) |
| **C2** | The same command **unsigned** is refused `command.unsigned` with the bar on |
| **C3** | A signature over a different value is refused `command.sig.invalid` |
| **C4** | A signature from a key not in `authorized-keys.jsonl` is refused `command.principal.unknown` |
| **C5** | A valid signed command from a principal the **rule does not name** is refused `principal-mismatch` |
| **C6** | Replaying C1's exact payload is refused `command.replay` |
| **C7** | With the bar **off**, the unsigned command from C2 is applied — proving the refusals came from the bar |

- [ ] **Step 1: write it · Step 2: run · Step 3: one deterministic injection per assertion · Step 4: all other gates · Step 5: commit**

---

## Chunk 5: Documents

### Task 7: say what is now true, and what is still not

- [ ] `ENTERPRISE.md` — the governance definition's "who authorized what" now holds on the command path **with the bar on**; add the gate to the list; update counts. **Do not** claim a command record: `NcmdOpcUaBridge` still has no ledger reference, and that is R2
- [ ] The "Authorization is direct principal grants" limitation stays, and gains the replay window as a named limit
- [ ] `ADOPTION.md` — phase 4 gains the bar; note it is opt-in like the others
- [ ] `README.md` — gate list, counts, badge

---

## Definition of done

- [ ] `mvn test` green; the pre-R1 `CommandAuthorizerTest` cases unchanged and still passing
- [ ] `run-command-identity-gate.sh` PASS, **every C1–C7 proved by injecting its defect**
- [ ] All seven pre-existing runtime gates still PASS, still unsigned
- [ ] Docs state the replay window as a window, and do not claim a command ledger

## What R1 explicitly does not fix

| | Round |
|---|---|
| Commands still leave no tamper-evident record — the subject reaches a log line and an MQTT response, nothing durable | R2 |
| Key bootstrap, distribution and revocation remain out of band; the trust anchor is a plaintext file | axis 6 / 10 |
| Replay is bounded by a window, not prevented | later |
| Roles and attributes — authorization stays direct principal grants | open |
