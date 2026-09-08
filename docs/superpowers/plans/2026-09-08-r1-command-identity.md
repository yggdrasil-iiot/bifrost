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

| **Log-only lets refusals through** | `NcmdOpcUaBridge.refuse()` returns **null** when `logOnly`, and the caller does `if (refused != null) return refused;` then falls through and applies. Any refusal routed through `refuse()` is therefore *shadowed*, not enforced. This is the single most important fact in this plan — see decision (a) |
| `CommandRequest` construction sites | **10, in 4 files**: `CommandAuthorizerTest`, `OpaCommandAuthorizerTest`, `NcmdBridgePolicyTest`, `NcmdOpcUaBridge`. With a delegating constructor, **none of them break** |
| `CommandAuthorizerTest`'s shape | `policy(Rule...)` is a **factory method**, not a field; `req(...)` is **3-arg**; its vocabulary is `Acme:Busan:Press` / `L1:GW3` / `ops` / `eng`, **not** heimdall's `recipe-writer` |
| Reads never reach authorization | `handle()` short-circuits QUERY/`op=read` before the authz block, so no bar can apply to them |
| `PolicyGate.lint` does not require a principal | It checks default-deny, duplicate ids, empty constraints and `*/*` over-grant — nothing about `principal` |

### Decisions locked here

**(a) The signature bar refuses DIRECTLY. It must not go through `refuse()`.**

This is the correction that matters most. The plan's first draft claimed the composition was fail-closed because `REQUIRE_SIGNED_COMMAND` rejects an unsigned command before `authorize` runs. **That would have been false**, because `refuse()` returns null under `ENFORCEMENT_LOG_ONLY` and the caller falls through: with both flags on, an unsigned command would have been logged `would-deny` and then **applied**, arriving at `authorize` with `subject == null` and skipping the principal check — exactly the hole the claim denied.

The right behaviour follows two precedents already in the code:

- the malformed-payload rejection is deliberately **not** shadowed (`NcmdOpcUaBridge` javadoc: *"There is no command in a payload that carries no command metric, so there is nothing to let through"*)
- `NcmdOpcUaBridgeMain` already documents the `REQUIRE_*` activation bars as **orthogonal** to log-only: *"the bars decide which ledger the edge will trust before it binds, log-only decides whether commands are refused"*

`REQUIRE_SIGNED_COMMAND` is a bar of the same kind. It decides **what the edge will accept as a command at all**, which is an authentication question, not a policy verdict — and log-only inverts verdicts. So all four new refusals return an `NcmdResponse` directly. **A test must pin this: bar on + log-only on ⇒ still refused.**

**(b) Principal matching is checked only when a subject is asserted.**
Every rule in `policy.json` names a principal and every pre-R1 caller passes none, so unconditional matching would fail 16 `CommandAuthorizerTest` cases and seven gates on day one. A null subject means "not asserted". What makes the composition fail-closed is decision (a), and **only** decision (a) — write that into both javadocs, because the isolated method looks weaker than the system it sits in.

**(c) Reads are out of scope, and the docs must say so.**
`handle()` short-circuits reads before authorization, so the bar cannot apply to them. That is defensible — a read is observation, and the existing code already says so — but "every command carries a verified requester" would be false as written. The claim is about the **write** path.

**(d) The subject comes from a signed envelope, not from the broker.**
MQTT does not tell a subscriber who published. A signed envelope is broker-neutral, verifiable by the edge itself, and reuses the Ed25519 machinery already trusted for activation. The broker ACL is worth projecting as defence in depth, but the record cannot depend on it.

**(e) First-match with deny-on-mismatch means one principal per (target, command).**
A second rule granting the same node to a different principal becomes unreachable, because the first match returns. That follows the documented first-match semantics and is harmless for today's `policy.json`, but it is a real constraint on the policy language and is chosen here rather than stumbled into.

**(f) Replay is bounded by a window, and the window is weaker than it sounds.**
The envelope binds `cmdId`, and the bridge refuses a repeat from a bounded LRU. Three limits go in the docs, not just the first: an attacker who waits past the window succeeds; **a bridge restart empties it**; and a payload with no `cmdId` would be replayable against every other uuid-less payload, so a null or blank `cmdId` is itself a refusal when the bar is on.

---

## Chunk 1: A command has a subject

### Task 1: `CommandRequest` carries it; `CommandAuthorizer` matches it

**Files:**
- Modify: `core/src/main/java/dev/krillin/bifrost/core/acl/CommandRequest.java`, `CommandAuthorizer.java`
- Test: `core/src/test/java/dev/krillin/bifrost/core/acl/CommandAuthorizerTest.java`

- [ ] **Step 1: Write the failing tests**

Written against the real test class: `policy(...)` is a factory, `req(...)` is 3-arg, and the vocabulary is `gw3` / `ops` / `eng`. Add a 4-arg `req` overload alongside the existing one rather than changing it.

```java
    private CommandRequest req(String command, Object value, String type, String subject) {
        return new CommandRequest(gw3, command, value, type, subject);
    }

    @Test void subject_matching_rule_principal_is_allowed() {
        CommandPolicy p = policy(new Rule("r1", "ops", gw3, "Setpoint/Rpm",
                new Constraint("Double", 0.0, 3000.0)));
        assertTrue(auth.authorize(p, req("Setpoint/Rpm", 1500.0, "Double", "ops")).allowed());
    }

    @Test void subject_not_matching_rule_principal_is_denied() {
        CommandPolicy p = policy(new Rule("r1", "ops", gw3, "Setpoint/Rpm",
                new Constraint("Double", 0.0, 3000.0)));
        Decision d = auth.authorize(p, req("Setpoint/Rpm", 1500.0, "Double", "eng"));
        assertFalse(d.allowed());
        assertTrue(d.reason().startsWith("principal-mismatch"), d.reason());
    }

    /**
     * Backward compatibility, and load-bearing: every pre-R1 caller passes no subject. Null means
     * "not asserted", NOT "anonymous is fine" — REQUIRE_SIGNED_COMMAND is what makes an unasserted
     * subject impossible, and it refuses before this method is reached.
     */
    @Test void no_subject_means_the_principal_is_not_checked() {
        CommandPolicy p = policy(new Rule("r1", "ops", gw3, "Setpoint/Rpm",
                new Constraint("Double", 0.0, 3000.0)));
        assertTrue(auth.authorize(p, req("Setpoint/Rpm", 1500.0, "Double")).allowed());
    }

    @Test void a_rule_with_a_wildcard_principal_admits_any_subject() {
        CommandPolicy p = policy(new Rule("r1", "*", gw3, "Setpoint/Rpm",
                new Constraint("Double", 0.0, 3000.0)));
        assertTrue(auth.authorize(p, req("Setpoint/Rpm", 1500.0, "Double", "anyone")).allowed());
    }
```

- [ ] **Step 2: Run to verify red**

Run: `mvn -q -pl core test -Dtest=CommandAuthorizerTest -Dsurefire.failIfNoSpecifiedTests=false`
Expected: FAIL — no 5-arg `CommandRequest`

- [ ] **Step 3: Implement**

`CommandRequest` gains `String subject` as the last component, plus a **non-canonical delegating constructor** (not a *compact* one — a compact constructor cannot change arity):

```java
public record CommandRequest(Target target, String command, Object value, String type, String subject) {

    /** Pre-R1 shape: no subject asserted. Keeps all 10 existing construction sites compiling. */
    public CommandRequest(Target target, String command, Object value, String type) {
        this(target, command, value, type, null);
    }
}
```

**None of the 10 existing construction sites change.** In `CommandAuthorizer`, inside the rule loop after the command match:

```java
            // Checked only when the caller asserted a subject. A null subject is "not asserted",
            // not "anonymous is fine": REQUIRE_SIGNED_COMMAND is what makes an unasserted subject
            // impossible, and it refuses the command outright before this method is reached — it
            // does NOT route through the bridge's refuse(), which log-only would shadow.
            if (req.subject() != null && !principalMatches(r.principal(), req.subject())) {
                return Decision.deny("principal-mismatch [" + r.id() + "]");
            }
```

**The reason string carries the rule id, not the expected principal.** `refuse()` puts this string into the NDATA response as well as the log, and that response goes to a broker this design's own premise says authenticates nobody — naming the authorized principal there hands an unauthenticated prober the answer for each rule.

`principalMatches` treats null or `"*"` as any, mirroring `fieldMatches`.

- [ ] **Step 4: Green, then the whole reactor** — `mvn -q test`
- [ ] **Step 5: Commit**

### Task 1b: `PolicyGate` lint — a rule without a principal

**Files:** `gates/src/main/java/dev/krillin/bifrost/gates/PolicyGate.java` + its test

Once the principal is load-bearing, a rule that omits it or sets `"*"` grants every *signed* principal — the new enforcement is one missing JSON key away from nothing, and nothing lints it today.

- [ ] **Step 1: failing test · Step 2: red · Step 3: add `[lint-5]` requiring a non-blank, non-`*` principal · Step 4: green · Step 5: commit**

---

## Chunk 2: The envelope

### Task 2: `CommandEnvelope` — canonical preimage, sign, verify

**Files:**
- Create: `core/src/main/java/dev/krillin/bifrost/core/acl/CommandEnvelope.java`
- Test: `core/src/test/java/dev/krillin/bifrost/core/acl/CommandEnvelopeTest.java`

**The value encoding must be pinned here or C1 fails on its first run.** The signer parses `1500` from a command line into a `Double`; the verifier reads an `Object` off the decoded metric. `"1500"` and `"1500.0"` are different preimages. **Rule: the preimage takes the value as `String.valueOf(Object)` applied to the *typed* value** — the signer must construct the same typed object (a `Double` for `Double`) before signing. Test it with the exact literal the gate uses.

- [ ] **Step 1: Write the failing tests**

Cover: a good signature verifies; a tampered value does not; a tampered command does not; a different `cmdId` does not; a key that is not the named principal's does not; an unknown principal yields a distinct outcome from a bad signature; and a **field-boundary** case — `cmdId="a", command="b"` must not verify against `cmdId="ab", command=""`.

- [ ] **Step 2: Run to verify red**
- [ ] **Step 3: Implement**

```java
    private static final char SEP = '';                        // as LedgerChain
    private static final String NULL_SENTINEL = " null ";

    /**
     * Ordered, delimiter-joined, NOT JSON — so signer and verifier cannot diverge on encoding.
     *
     * <p>Carries {@code LedgerChain}'s limitation forward unchanged: this assumes no field value
     * contains the SEP delimiter or the null sentinel. A value that does could collide with a
     * different field split, and that is outside this envelope's threat model in the same way and
     * for the same reason.
     */
    public static String preimage(String group, String edge, String cmdId,
                                  String command, String value, String type) { … }
```

plus `sign(...)` returning base64 and `verify(AuthorizedKeys, subject, sig, …)` returning a small verdict that **distinguishes unknown-principal from bad-signature** — C3 and C4 depend on that distinction.

- [ ] **Step 4: Green · Step 5: Commit**

### Task 3: The bridge verifies it, behind a bar

**Files:**
- Modify: `heimdall/.../NcmdOpcUaBridge.java`, `NcmdOpcUaBridgeMain.java`
- Test: `heimdall/.../NcmdOpcUaBridgeTest.java`

**The seam, named explicitly.** `NcmdOpcUaBridgeMain.Config` gains `boolean requireSignedCommand` (env `REQUIRE_SIGNED_COMMAND`, via the existing `flag(...)` helper) and `int replayWindow` (`HEIMDALL_REPLAY_WINDOW`, default 1024, via `intEnv`). **Three existing tests construct `Config` directly** — `LoadConformanceActivationTest`, `NcmdOpcUaBridgeMainDefaultsTest` ×2 — and new components break their arity, as happened in both R0 and R3. Add the values to each.

`NcmdOpcUaBridge` takes `requireSignedCommand`, `replayWindow` and an `AuthorizedKeys` on the **widest constructor only**, with the existing narrower ones delegating (`false, 1024, null`) exactly as the R0 note in that file describes. **None of the 9 existing bridge-construction sites change.**

When the bar is ON, `handle(...)` verifies **before** building the `CommandRequest`, and each failure **returns directly rather than calling `refuse()`** (decision (a)):

| Condition | Reason code |
|---|---|
| no `sub`/`sig` metric property | `command.unsigned` |
| null or blank `cmdId` | `command.unsigned` (nothing to bind a signature to) |
| `sub` not in `authorized-keys.jsonl` | `command.principal.unknown` |
| signature does not verify | `command.sig.invalid` |
| `cmdId` seen before | `command.replay` |

When OFF, `handle(...)` is byte-for-byte what it is today — subject null, no verification — which is what keeps the seven existing NCMD gates meaningful.

**Replay guard.** A `Collections.synchronizedMap` over a `LinkedHashMap` in access order with `removeEldestEntry`. **Synchronization is required, not defensive**: R0 made the apply path striped across four `CommandExecutor` threads, so two commands genuinely arrive concurrently. Its javadoc must state the three limits from decision (f).

- [ ] **Step 1: Write the failing tests** — one per reason code; a replay test; **bar on + log-only on ⇒ still refused** (the decision-(a) test); and "bar off ⇒ behaviour unchanged"
- [ ] **Step 2: red · Step 3: implement · Step 4: green · Step 5: whole suite · Step 6: commit**

### Task 4: A signing publisher

**Files:** Modify `heimdall/.../RogueNcmd.java` — optional `--sign <principal> <keyfile>`

Extend it rather than adding a near-copy: every gate already uses it, and two publishers differing by one property will drift. The signing itself is `CommandEnvelope.sign` from Task 2, so it is already unit-tested; this task is wiring plus the two metric properties.

- [ ] **Step 1: implement · Step 2: verify by hand against a live broker · Step 3: commit**

---

## Chunk 3: The broker half

### Task 5: `acl-project` CLI

**Files:** `gates/src/main/java/dev/krillin/bifrost/gates/` — follow `GatesCli`'s dispatch, and note it **duplicates its usage string** at two places, both of which need the new verb.

**The honest scope, stated before writing it.** HiveMQ CE ships no ACL engine; the compose file runs the bundled allow-all extension. The blocker is not that an extension cannot be downloaded — the repo already pulls `hivemq/hivemq-ce:latest` over the network. The blocker is that **`hivemq-ce` is the shared broker for all twelve broker gates**, and the compose file says so in as many words; turning allow-all off to enforce a projected ACL breaks every one of them unless a second profiled service is added. The projected `AclEntry(principal, topic, PUBLISH)` also has no MQTT-username mapping.

So this task lands the projection as a **verified artifact**: a CLI caller and an emitted file. **The delta over today is narrow and must be described as such** — `BrokerAclProjectorTest` already exercises the projector, so what is new is a caller and an output, not enforcement. There is no broker leg in Chunk 4 and no `C8`; Chunk 5 must not imply one.

- [ ] **Step 1: implement · Step 2: test the emitted file · Step 3: commit**

---

## Chunk 4: Evidence

### Task 6: `run-command-identity-gate.sh`

Reuse the R0/R3 idiom: `cygpath` shim, `fail`, `kill_by_jvmarg`, count-based assertions, **a fresh log per bridge run**, and never grep an accumulating log without a baseline.

**Trust-anchor staging.** `AuthorizedKeys.load(root)` reads `<root>/identity/authorized-keys.jsonl`, and `REGISTRY_PATH` is the *same* root `DefinitionStore` reads `udt/` from. So the gate cannot point `REGISTRY_PATH` at a scratch directory holding only keys — it must **stage a full registry copy** (`udt/`, `conformance/`, `policy.json`, plus the new `identity/`), which is the `stage_reg` idiom `run-activation-authz-gate.sh` already uses. Mint **three** principals: `recipe-writer` (named by the rules), a second registered principal that no rule names, and one key that is never registered.

| | Asserts |
|---|---|
| **C1** | A correctly signed command from `recipe-writer` is applied — APPLY count **increase** |
| **C2** | The same command unsigned is refused `command.unsigned`, bar on |
| **C3** | A signature over a different value is refused `command.sig.invalid` |
| **C4** | A `sub` naming a principal **absent from the trust anchor** is refused `command.principal.unknown` — distinct from C3, which is a *registered* name with a bad signature |
| **C5** | A validly signed command from the **second registered principal**, which the rule does not name, is refused `principal-mismatch` |
| **C6** | Replaying C1's exact payload is refused `command.replay` |
| **C7** | Bar **off** (own bridge run, own log file): the C2 command is applied — proving the refusals came from the bar |
| **C8** | Bar on **and `ENFORCEMENT_LOG_ONLY=on`**: the unsigned command is still refused and **not** applied. This is decision (a), and it is the assertion the first draft of this plan would have failed |

- [ ] **Step 1: write it · Step 2: run · Step 3: one deterministic injection per assertion**

| Injection | Must fail |
|---|---|
| Drop the `sub` property in the signing publisher | C1 |
| Make the missing-signature branch fall through instead of returning | C2 |
| Sign over the untyped value (`String.valueOf(rawArg)`) | C3 |
| Have `verify` return bad-signature for an unknown principal | C4 |
| Ignore `req.subject()` in `CommandAuthorizer` | C5 |
| Skip the LRU insert | C6 |
| Ignore `REQUIRE_SIGNED_COMMAND` (always on) | C7 |
| Route the unsigned refusal through `refuse()` | C8 |

- [ ] **Step 4: all other gates · Step 5: commit**

---

## Chunk 5: Documents

### Task 7: what is now true, and what is still not

- [ ] `ENTERPRISE.md` — the governance definition's "who authorized what" now holds **on the write path, with the bar on**. Say all three qualifiers. **Do not claim a command record**: `NcmdOpcUaBridge` still has no ledger reference, and that is R2
- [ ] The "Authorization is direct principal grants" limitation stays, and gains: the replay **window** (bounded, restart-clearing), reads not covered, and the broker projection being an artifact rather than enforcement
- [ ] `ADOPTION.md` — phase 4 gains the bar, opt-in like the others
- [ ] `README.md` + `ENTERPRISE.md` line 13 — gate list, gate count 17→18, test count, badge

---

## Definition of done

- [ ] `mvn test` green; the 16 pre-R1 `CommandAuthorizerTest` cases unchanged and passing
- [ ] `run-command-identity-gate.sh` PASS, **every C1–C8 proved by injecting its defect**
- [ ] **All seven pre-existing NCMD gates still PASS**, still unsigned — `run-activation`, `run-composable-conformance`, `run-edge-resilience`, `run-lineage`, `run-ncmd-runtime`, `run-write-exclusivity`, `run-yggdrasil-full-loop`
- [ ] Docs state the replay window as a window, say reads are not covered, and do not claim a command ledger or broker enforcement

## What R1 explicitly does not fix

| | Round |
|---|---|
| Commands still leave no tamper-evident record — the subject reaches a log line and an MQTT response, nothing durable | R2 |
| Reads are not covered: `handle()` short-circuits them before authorization | open |
| Key bootstrap, distribution and revocation remain out of band; the trust anchor is a plaintext file | axis 6 / 10 |
| Replay is bounded by a window that a restart clears, not prevented | later |
| The broker ACL is projected, not enforced — one shared broker serves twelve gates on an allow-all extension | later |
| `OpaCommandAuthorizer` stays subject-blind; R1 does not extend the OPA path | later |
| Roles and attributes — authorization stays direct principal grants | open |
