# Adopting this at a running site

[`ENTERPRISE.md`](ENTERPRISE.md) is a board of axes and their evidence. This is the other
question: given a plant that is **already running**, in what order do you put any of it in, and
what has to be true before each step?

Nothing here has been done at a plant. What follows is a sequence derived from the code as it
stands — the constraints are checked against the source, and the places where the current build
cannot support the sequence are named rather than smoothed over.

---

## The rule that governs everything else

**Nothing installed in the first phases may be capable of stopping the line.**

Break that and the rest of the plan does not matter. The moment a site is asked to change
production to satisfy a new tool, the tool is the problem and the project ends. Every ordering
decision below falls out of this one rule.

## Three facts in the code that fix the order

**Huginn cannot stop anything, by construction.** It is `huginn.jar capture.pcap policy.yaml` —
offline pcap, not an inline device, and live capture is not built. Nothing it does can reach the
plant, which is what makes it the wedge. *Obtaining* the capture is a separate matter and not
risk-free: mirroring a port is a change to production network equipment and is scheduled like one.
The tool is inert; the tap is not.

**Heimdall enforces by default, and can be told not to.** In `NcmdOpcUaBridge`, command
authorization is deny-by-default and always on; conformance and the activation checks are the
opt-in bars (`REQUIRE_SIGNED_ACTIVATION`, `REQUIRE_ANCHORED_ACTIVATION`, both defaulting to
`false`). `ENFORCEMENT_LOG_ONLY` (also `false` by default) inverts the risk for the duration of a
rollout: a command that ①authz or ②conformance would refuse is logged as `LOG-ONLY would-deny` and
then **applied**. It exists for phase 4 below and for nothing else.

**Propagation is restart-scoped** ([why](ENTERPRISE.md#2-propagation-is-restart-scoped-on-purpose)).
In steady-state operation that is a limit worth stating. During a rollout it is an asset: the
blast radius of a bad policy is bounded by a restart you control, and every tier is reversible the
same way.

---

## The phases

| # | What goes in | Can it stop the line? | Exit criterion |
|---|---|---|---|
| 0 | Huginn on captures | **no** | new conduits stop appearing |
| 1 | The current model, declared | **no** | a model owner exists |
| 2 | Declared vs observed, reconciled | **no** | discrepancies are not all "the model was wrong" |
| 3 | Four-eyes on model changes, in CI | only a pull request | changes routinely carry an approver |
| 4 | Heimdall on one edge, log-only | **no** while log-only is on | Huginn coverage high enough to trust the derived allowlist |
| 5 | Signed, then anchored | yes, reversibly | each tier survives a week |
| 6 | Second site | yes | F1 holds on real hardware |

### 0 — Observe only

Take captures from a SPAN or TAP port and run Huginn. Declare nothing, block nothing.

The output is **the enumeration a declaration gets written from** — which paths exist, so that
phase 1 can say deny-by-default and mean something. It doubles as the observed half of a 62443
conduit register, which matters for a non-technical reason: it makes the first step an artifact the
auditors already ask for, rather than a project premised on the site's process being wrong. There
is very little to argue with.

**The goal is a writable declaration, not a complete picture of the plant.** Paths that will be
governed by change control or by segmentation instead should be written down as deliberate
exclusions here, while it is cheap to say so. An exclusion someone decided is governed; a path
nobody noticed is not.

**Exit when new conduits stop appearing.** Shift patterns, the monthly batch and a maintenance
window all have to happen at least once. If week four is still producing new paths, the duty cycle
has not been captured and every later phase would be built on a list that is missing rows.

**Collect two things, not one.** The captures, and an inventory of **product and gateway
versions** for everything that will hold a copy of a governed model — Ignition, Kepware, ThingWorx,
the historian. Version decides which vendor-side direction is even available (the Ignition tag/UDT
export endpoint does not exist before 8.3.2; parts of the Kepware Configuration API need particular
6.x versions), so a plan written without it will promise a reconciliation some site cannot perform.
It is also the cheapest thing to collect and the easiest to forget.

**Cost to the site:** somebody has to pull the captures and hand them over. Without live capture
this phase has a person in it.

### 1 — Declare what already exists

Transcribe the current state into a Bifrost registry — **the actual model, not the intended one.**
The three `TemplateAdapter` implementations exist for this direction; a site fronted by an
interface tool such as Kepware or Ignition has one already-normalized source to read instead of
one export format per PLC vendor.

**The first version of the model must pass the gate with the plant untouched.** A gate that is red
on day one is asking the site to change production for the tool's benefit.

The deliverable is a `git log` of the model. It is the first time anyone can diff it.

**This is where the real argument happens: who owns the model.** It should happen here, while
nothing is enforced and the argument is cheap. Reported multi-site experience puts the hard part
in the data model and its ownership rather than the technology, and this is the phase that tests
whether that owner exists. **If no owner emerges, stop.** What gets built instead is a second
spreadsheet.

### 2 — Reconcile declaration against observation

Huginn checks the declared map against what actually crossed the wire. Every discrepancy is either
the model being wrong or something happening that should not be. **Both are findings the site
wants**, which is what makes this phase worth doing on its own even if the project stops here.

**This is the phase that earns the right to enforce.** A gate in the write path is not something a
site grants to a tool that has not yet demonstrated it understands the plant better than the
spreadsheet does.

**A second reconciliation belongs in this phase**, against the vendor tools rather than the wire.
Wherever a ThingWorx, Kepware or Ignition holds its own copy of a governed model, read that copy
back and compare it — read-only, same as the traffic side. It answers the question that decides
whether any of this is vendor-independent in practice: *which copy is being hand-edited*. See
[`ENTERPRISE.md` §13](ENTERPRISE.md#13-governed-model-vs-vendor-runtime), which is open, and note
that some products will only ever support this direction and never a push.

**This is also the first phase that needs code that does not exist.** Huginn reads its own
`CommunicationPolicy` YAML and holds no reference to the governed registry, and nothing reads a
vendor's configuration back at all.

### 3 — Gate the change process, not the runtime

Put the activation ledger and four-eyes separation of duties on **changes to the model**, in CI —
tiers T3 and T4. The only thing that can be blocked is a pull request; nothing sits in the plant's
write path.

This is where the organization actually changes: a recipe change acquires an approver and a trail.
It is also the cheapest phase to reverse, because reversing it means turning off a branch
protection rule.

### 4 — Heimdall in the path

This is where the edge acquires the ability to refuse a command, so it is the phase to be
careful with. **Three things flatten it, and they are meant to be used together.**

**Start in log-only.** `ENFORCEMENT_LOG_ONLY=on` makes Heimdall evaluate every command and refuse
none: what would have been denied is logged as `[BRIDGE] LOG-ONLY would-deny cmd=… reason=…` and
also rides back on the command's own response detail, so the operator who issued it learns it
would have been blocked without anything having been blocked. The applied effect is identical to
having no Heimdall in the path at all. Two things are deliberately **not** covered — a malformed
payload carrying no command metric is still rejected (there is no command in it to let through),
and the startup ledger-trust checks still fail closed, because a bridge that cannot trust the
model it is checking against should not start rather than wave traffic past. The startup line
`[BRIDGE] enforcement = LOG-ONLY …` prints in both states, so which mode an edge is in is always
readable from its log.

**The edge also has to survive the night it is not being watched.** Log-only inverts *refusal*; it
does nothing about *unavailability*, and this phase's rule is about the line stopping for any
reason. Four paths that could stop it have been closed, and `run-edge-resilience-gate.sh` proves
each by killing something and requiring recovery with no human action: the edge now starts even
when its OPC-UA server is down (it used to exit, and would crash-loop under a restart policy),
reconnects to the broker **and resubscribes** (an automatic reconnect without the resubscribe comes
back connected and deaf, which reads healthy in the log), rebuilds a lost OPC-UA session by itself,
and answers a command it cannot apply with `plant-unreachable` rather than `conformance-error` —
an outage used to send the operator to look at the model. A retained will on
`bifrost/{group}/STATUS/{edge}` lets the broker announce a death the process never noticed, and
`/healthz` reports both legs, so an edge that is connected to the broker but blind to the plant
reads unhealthy. Every assertion in that gate was checked by injecting its defect; two of them were
found to be vacuous that way and fixed.

**What this does not change.** The startup ledger-trust checks still fail closed: a bridge that
cannot trust the model it checks against still refuses to start, and that is deliberate — an
invisible machine is transient, an untrustworthy model is not. There is still no break-glass. The
container in `heimdall/Dockerfile` is built but exercised by no gate.

**Then the two that were always part of the plan.**

**Narrow the scope to one edge.** `SPB_GROUP` and `SPB_EDGE` are per-edge, so the first deployment
covers one line or one cell and the blast radius is that one.

**Make the edge the only way in.** Until the controlled nodes are writable *only* by the governed
identity, the edge governs the clients that choose to use it and nothing else — see
[`ENTERPRISE.md` §12](ENTERPRISE.md#12-write-path-exclusivity), which is open, and which is where
the certificate-lifecycle gap actually bites. An edge deployed without this is worth having, because
the plant's own tooling is the client that matters, but it is not yet a boundary and should not be
described as one.

**Derive the initial policy from what phase 2 observed — after its findings are resolved.** This is
the reason phase 2 is not skippable: an allowlist derived straight from observation encodes whatever
bypass already exists *as a permission*, and a governed registry is a bad place to launder one. Every
phase-2 discrepancy has to end as either a corrected model, a closed path, or a written exclusion
before it becomes a rule. An allowlist built from the traffic that legitimately occurs
**cannot deny anything on day one** — day-one refusal becomes structurally
impossible rather than merely unlikely. Enforcement then arrives by **subtraction**: rules are
removed one at a time, and each removal is a reviewable diff with a named approver, which is
exactly what phase 3 built the machinery for.

**The entry gate is Huginn's coverage number.** A derived allowlist contains only what Huginn
decoded; whatever it could not decode is a hole in the list, and a hole in the list is a refusal.
Huginn already reports coverage on every run and its `UNDECIDABLE` count does not affect its exit
code, so that number is available to be used as the gate for entering this phase.

**One thing does not line up in the current build.** Huginn decodes Modbus/TCP and S7comm;
Heimdall guards Sparkplug NCMD writes onto OPC UA. **They are different surfaces**, so the derived
allowlist described above cannot be built today — the principle holds, the components do not meet.
Closing it means either Huginn decoding the surface Heimdall guards, or the allowlist coming from
a capture of that surface. This is more specific than "Huginn is not wired to Bifrost", and it is
a prerequisite for this phase rather than a nice-to-have.

### 5 — Raise the ladder

`REQUIRE_SIGNED_ACTIVATION` first, then `REQUIRE_ANCHORED_ACTIVATION`. **One at a time, each
reversible by a restart.**

The measurements in [§11](ENTERPRISE.md#11-audit-query-at-scale) settle one question that would
otherwise stall this phase: anchoring costs nothing on top of signing, and the expensive half of
the `git` anchor store (about half a second, on activation) lands on an event that happens ten
times a day, while the check that runs at every edge bind is the cheap one. **Performance is not a
reason to defer either tier.**

### 6 — Second site

F1 — `site ⊨ enterprise` — only becomes real here; until now there has been one site and a
template with nothing to specialize. This is also the phase the cited "4–8 weeks per subsequent
plant" applies to, and the phase where this document's claim narrows to what it can actually
support: **this shortens the governance part of a site rollout, not the rollout.**

---

## What the current code cannot do in this plan

| Gap | Bites at | Status today |
|---|---|---|
| Huginn ↔ Bifrost seam, **including the surface mismatch** | phase 2, hard-blocks phase 4 | not built |
| Vendor-side verification (governed model vs vendor's copy) | phase 2 | [row 13](ENTERPRISE.md#13-governed-model-vs-vendor-runtime): not built |
| ~~Heimdall shadow / log-only mode~~ | phase 4 | **built** — `ENFORCEMENT_LOG_ONLY`, 10 tests |
| Certificate expiry and key rotation | phase 4–5 | [axis 10](ENTERPRISE.md#the-board): open, no mechanism |
| **Write-path exclusivity** — the edge is a chokepoint by convention | phase 4 | [row 12](ENTERPRISE.md#12-write-path-exclusivity): open, and **not this project's code to write**; itself blocked on the row above |

The middle row was named here as the one worth building first for adoption's sake, and it has
since been built — it was the smallest of the three and it is what turned phase 4 from a cliff into
a step. Of what is left, two rows are code this project owes and has not started. The last row is
not code at all.

**Why the last row is listed anyway.** Every other gap here is something this repository has to
build. Write-path exclusivity is not. What closes it is server-side write permission on the
controlled nodes, and — for protocols with no identity to authenticate — a network position, which
is what 62443 zones and conduits are for ([§12](ENTERPRISE.md#12-write-path-exclusivity)). No
amount of code here makes the governed edge exclusive. It belongs in this table because phase 4
installs a gate, and whether that gate is a gate is settled by the plant rather than by the gate.
It is also the clearest case of the general point: an adoption plan that lists only the software
it owes is not an adoption plan.

The struck-through log-only row meets the standard every *built* row on the
[`ENTERPRISE.md` board](ENTERPRISE.md#the-board) is held to: it names a script. `run-ncmd-runtime-gate.sh` T4 restarts the edge with
`ENFORCEMENT_LOG_ONLY=on` against a live HiveMQ broker and a live OPC-UA server, sends both rogues,
and asserts each is logged `would-deny` and then applied — with the live server witnessing the
out-of-range `Rpm=9999` landing on the node, which is the assertion that cannot be satisfied by a
bridge that is still blocking. T5 restarts without the flag and requires the rogue to be denied
again, because reversibility by restart is the property this plan actually leans on.

Both directions were checked by injecting the defect rather than by trusting the green: forcing
log-only ON makes seven existing enforcement tests fail, and forcing it OFF makes T4 fail.

The certificate row deserves a note against the board. `ENTERPRISE.md` gives axis 10 the trigger "any
deployment that outlives its first certificate", which reads like a late problem. Laid against
this sequence it is not: an OPC UA deployment acquires certificates in phase 4, so **the trigger
fires inside the rollout, not after it.**

## Abort criteria

One per phase, decided before starting it.

- **0** — week four still producing new conduits: fix the capture scope before going on.
- **1** — no model owner emerges: stop. The output would be a second spreadsheet.
- **2** — every discrepancy resolves to "the model was wrong": the model is not yet good enough to
  enforce, and phase 4 has not been earned.
- **4** — Huginn coverage too low for the derived allowlist to be trusted: do not enter.

## What this document does not claim

- **No calendar.** Only two duration figures here have a source: 6–18 months for a full federated
  deployment and 4–8 weeks per subsequent plant. Per-phase durations are not given, because
  inventing them would put the one unfounded number into a set of documents whose whole claim is
  that every figure has a source.
- **Not validated.** No part of this sequence has been run at a plant. It is derived from the
  code's constraints, which is a weaker thing than experience and should be read as such.
- **Phases 0–3 are the defensible part.** They need no new enforcement surface and each produces
  an artifact worth having on its own. Phases 4–6 depend on gaps named above as not built.

---

*Duration figures: multi-site UNS experience
([Automation World](https://www.automationworld.com/factory/iiot/article/33016191/unified-namespace-real-world-applications-and-challenges)).
Conduit register expectations: see [`ENTERPRISE.md` §5](ENTERPRISE.md#5-conduit-inventory) for sources.*
