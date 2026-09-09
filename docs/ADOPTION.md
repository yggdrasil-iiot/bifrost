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

**The governed conduits can be projected for Huginn to check.** `gates conduit-project <reg>
--edge <address> --bind <ref>=<address>` emits the `CommunicationPolicy` fragment saying the
governed edge is the only permitted writer of that equipment. Run Huginn with it and a write to
governed equipment from anything else is reported — including over a protocol the edge does not
speak, which is exactly the bypass phase 4 is worried about.

**The binding is the human input, and it is the whole seam.** Nothing on the wire says which IP is
`Line1-Mixer`; somebody has to say so, and the emitted file records that they did. Get it wrong and
the findings are wrong in a way no amount of capture fixes.

**Merge the fragment into the site policy — do not run it alone.** It says who may *write* the
governed equipment. Bifrost does not know which HMIs and historians may legitimately *read* it, so
on its own deny-by-default reports every one of them as a violation. And note what this is not:
**a finding is visibility, not enforcement.** Nothing blocks the bypass; it acquires an owner.

**A second reconciliation belongs in this phase**, against the vendor tools rather than the wire.
Wherever a ThingWorx, Kepware or Ignition holds its own copy of a governed model, read that copy
back and compare it — read-only, same as the traffic side. It answers the question that decides
whether any of this is vendor-independent in practice: *which copy is being hand-edited*.

**This now has a command.** `gates model-reconcile <reg> <ref> <version> --vendor <export>
--adapter <ignition|cfihos|aas> [--granularity per-object|whole-set]` reports divergence per member
— a missing member, an unexpected one, a retyped tag, a widened range, a repointed `semanticId` —
and exits 0 agreed, 1 diverged, 2 if it could not read either side.

**The export is handed over, exactly like the capture in phase 0.** Nothing connects to a running
product; a Composer export, an Ignition `tags/export` and a Kepware `GET` all produce a file, and
the file is the interface. That keeps this phase inert in the same way phase 0 is: the tool cannot
reach the plant, and obtaining the export is the part with a person in it.

**`--granularity` is a fact about the product, not about the file.** Kepware and Ignition can be
corrected per object; ThingWorx has no per-object write, so a correction re-imports an entity set.
The findings are the same either way — the export was parsed — but the cost of acting on them is
not, and the command says which it is. Declare it per product when you write the runbook.

**Two limits worth knowing before you rely on it.** A finding proves the two copies *disagree*, not
which is right: a site whose vendor copy has been hand-edited for two years may well find the
registry is the stale document, and deciding that is a human act with an owner. And the export
carries no Bifrost identity, so **you tell it which governed definition to compare against** — it
answers *"does this object agree"*, not *"is everything present"*. See
[`ENTERPRISE.md` §13](ENTERPRISE.md#13-governed-model-vs-vendor-runtime), now partial, and note that
the push direction still does not exist.

**Both halves of this phase are now half-built, and the remainders are different in kind.** The
vendor half has the comparison and not the fetch — somebody exports and hands the file over. The
Huginn half has the projection and the proof that Huginn acts on it, and what it does not have is
any shared protocol between the two tools: **the surface mismatch was routed around, not closed.**
Bifrost still holds no reference to Huginn and Huginn none to the registry. What crosses is an
artifact and one binding a human asserted.

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
invisible machine is transient, an untrustworthy model is not. The container in
`heimdall/Dockerfile` is built but exercised by no gate.

**Then the two that were always part of the plan.**

**Narrow the scope to one edge.** `SPB_GROUP` and `SPB_EDGE` are per-edge, so the first deployment
covers one line or one cell and the blast radius is that one.

**Record what the edge did.** `COMMAND_LEDGER_PATH` makes the edge write a chained record of every
command: an intent entry before the applier touches the plant, an outcome entry after. With
`REQUIRE_COMMAND_LEDGER` on, a command whose intent cannot be written is refused before the applier
runs — so a phase-4 edge cannot move the plant unrecorded. Like the other bars it is opt-in and
reversible by a restart, and like the signature bar it is **not** shadowed by log-only.

**What it is worth planning around.** The chain catches an edit, a mid-list deletion or a reorder;
it does **not** catch truncation, and nothing signs the entries. Two entries per applied command is
a different volume class from the activation ledger, and neither growth nor retention has been
measured — decide the archival story before this runs for a year.

**Know which operator issued the command.** `REQUIRE_SIGNED_COMMAND` makes the edge verify an
Ed25519 envelope on every write command and match it against the principal the rule names, so
"which operator issued this setpoint" has an answer. Opt-in and off by default, like the other bars
above it, and reversible by a restart in the same way — but **unlike them it is not shadowed by
log-only**, because it asks whether there is an identity to judge rather than rendering a verdict on
one. Rolling it out means minting a key per writer into the registry's `identity/` anchor first;
until every writer has one, turning the bar on refuses them all.

**Two limits to plan around.** Reads are not covered — observation short-circuits before
authorization. And the verified subject reaches a log line, not a ledger: the tamper-evident record
still covers model activation and not the commands themselves.

**Make the edge the only way in.** Until the controlled nodes are writable *only* by the governed
identity, the edge governs the clients that choose to use it and nothing else. Both halves of that
now exist to be turned on: the edge presents an X.509 identity when `HEIMDALL_IDENTITY_DIR` is set,
and a server told to require it refuses another client's write while still serving its reads —
`run-write-exclusivity-gate.sh` proves the pair end to end. **Configuring the site's own server is
still the site's work**, and it is untested here against anything but this repository's sim; on
Modbus/TCP nothing changed, because there is no identity to present. See
[`ENTERPRISE.md` §12](ENTERPRISE.md#12-write-path-exclusivity), now partial, and where the
certificate-lifecycle gap bites hardest: that identity is self-signed and cannot be rotated. An edge
deployed without any of this is still worth having, because the plant's own tooling is the client
that matters, but it is not a boundary and should not be described as one.

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

**Mint the break-glass duty key before you need it.** Four-eyes is what phase 3 bought, and at 03:00
with one person on site it is also what stops the line from coming back. The answer is not to
weaken it but to **move it earlier in time**: `gates activation duty-key-mint` has two registered
people mint a duty key ahead of the emergency, and afterwards one person can activate alone by
signing with their own key plus the duty key. Grant that principal `break_glass_approve` and
**never** `approve` — a policy that gives it both over overlapping resources is refused at load,
because a principal holding both could simply approve normally and the emergency would never be
recorded as one. The marking is therefore derived from policy rather than claimed by whoever ran
it, and the entry says `BREAK_GLASS` in the ledger, on the control-plane console and in the edge's
own log at bind time. `scripts/run-break-glass-gate.sh` proves it, including that the ledger still
verifies at all three tiers afterwards and that the edge still binds — an emergency that leaves the
line unable to start is not a break-glass.

**Retire a duty key by removing its policy grants — never by deleting its key line.** Deleting a
principal's line from `authorized-keys.jsonl` retroactively breaks every ledger entry it ever
signed, `identity verify-signed` reports `identity.key.unregistered`, and every edge bound to that
target refuses to start. The ledger is append-only, so this is not recoverable by re-adding a new
key. Removing the grants leaves the history verifiable and stops the key being usable, which is what
revocation actually needs to mean here. B9 in that gate exists to prove this rather than assert it.

**Rotate a signing key with `gates identity rotate-key`, and paste the whole block it prints.** The
instruction above now has a mechanism behind it. The command mints the successor and prints every
line for that principal — the predecessor re-emitted with a `notAfter` stamp, then the successor —
and you replace exactly those lines. A key past its `notAfter` can no longer sign anything, while it
goes on verifying every entry it already signed, which is what makes retiring it safe. `K2` and `K3`
in `scripts/run-key-rotation-gate.sh` prove both halves, and `K5` proves the edge still boots on a
registry where the signer of the active version has since been retired.

**Rotation is not revocation, and the difference matters at 03:00.** A retired key still
authenticates its own past. If a key is believed *stolen* rather than merely old, rotating it stops
it signing anything new and does nothing about what it already signed — this repository has no
answer for that, because invalidating past signatures needs a time source the site trusts.

**Renew the edge certificate before it expires, and change the server first.** `EdgeIdentity show`
reports the days remaining; the edge prints them at every boot and warns from 30 days out
(`HEIMDALL_CERT_WARN_DAYS`), with `cert_days_remaining` on `/healthz` going negative once it has
lapsed. `EdgeIdentity renew` mints the successor, keeps the predecessor on disk and prints both
thumbprints. **The order is the whole procedure:**

1. `renew` — the running edge is untouched, still presenting the old certificate
2. add the **new** thumbprint to the OPC-UA server's trust list, keeping the old one
3. restart the edge, which now presents the new certificate
4. remove the old thumbprint once the edge is up

Steps 2 and 3 in that order are what makes this not an outage: the overlap, with the server trusting
both for a while, is the only reason a renewal does not stop the line. Doing 3 before 2 presents a
certificate the server has never heard of, and every write is refused until it is told. An expired
certificate does **not** stop the edge — it is diagnosed, loudly — because a lapsed transport
credential is an operational fault and failing closed on one would turn a missed renewal into a
planned outage.

### 6 — Second site

F1 — `site ⊨ enterprise` — only becomes real here; until now there has been one site and a
template with nothing to specialize. This is also the phase the cited "4–8 weeks per subsequent
plant" applies to, and the phase where this document's claim narrows to what it can actually
support: **this shortens the governance part of a site rollout, not the rollout.**

---

## What the current code cannot do in this plan

| Gap | Bites at | Status today |
|---|---|---|
| ~~Huginn ↔ Bifrost seam~~ | phase 2, hard-blocks phase 4 | **built in part** — `gates conduit-project` emits the governed conduits as the policy Huginn reads, and `run-huginn-seam-gate.sh` runs the real Huginn to prove a bypass is reported. **The surface mismatch is not closed, it is routed around**: the two tools still share no protocol, and what crosses between them is a file plus one declared binding |
| Vendor-side verification (governed model vs vendor's copy) | phase 2 | **built in part** — `gates model-reconcile` compares an export against the registry ([row 13](ENTERPRISE.md#13-governed-model-vs-vendor-runtime): partial). **The fetch is not built**, so somebody exports and hands the file over |
| ~~Heimdall shadow / log-only mode~~ | phase 4 | **built** — `ENFORCEMENT_LOG_ONLY`, 10 tests |
| ~~Certificate expiry and key rotation~~ | phase 4–5 | **built in part** — `identity rotate-key` and `EdgeIdentity renew`, with `run-key-rotation-gate.sh` ([axis 10](ENTERPRISE.md#10-certificate-expiry-and-key-rotation): partial). **No CA and no enrolment**, so a renewal is manual and the successor thumbprint reaches the server out of band |
| ~~Write-path exclusivity — the edge has no identity to present~~ | phase 4 | **built** — `EdgeIdentity` + `run-write-exclusivity-gate.sh`. The other half, the server configuration, is still the site's ([row 12](ENTERPRISE.md#12-write-path-exclusivity): partial) |

The log-only row was named here as the one worth building first for adoption's sake, and it has
since been built — it was the smallest and it is what turned phase 4 from a cliff into a step. Two
rows are still code this project owes and has not started; the certificate row joined the struck-out
ones in part, and its remainder is an integration rather than a gap.

**The last row was listed here as "not this project's code to write", and that was wrong.** The
reasoning was that what closes it is server-side write permission and — for protocols with no
identity to authenticate — a network position, which is what 62443 zones and conduits are for. Both
of those are true and both are still the plant's. What the reasoning missed is that **a lock needs a
key**: the edge connected anonymously and could not present an identity at all, so a site that
configured its server exactly as [§12](ENTERPRISE.md#12-write-path-exclusivity) asks would have
locked out the edge the configuration exists to privilege. That half was always this repository's,
and it is now built and gated.

The general point the row was making survives intact, and is if anything sharper: phase 4 installs a
gate, and whether that gate is a gate is settled by the plant rather than by the gate. An adoption
plan that lists only the software it owes is not an adoption plan — but it must not mistake software
it owes for someone else's problem either.

The struck-through log-only row meets the standard every *built* row on the
[`ENTERPRISE.md` board](ENTERPRISE.md#the-board) is held to: it names a script. `run-ncmd-runtime-gate.sh` T4 restarts the edge with
`ENFORCEMENT_LOG_ONLY=on` against a live HiveMQ broker and a live OPC-UA server, sends both rogues,
and asserts each is logged `would-deny` and then applied — with the live server witnessing the
out-of-range `Rpm=9999` landing on the node, which is the assertion that cannot be satisfied by a
bridge that is still blocking. T5 restarts without the flag and requires the rogue to be denied
again, because reversibility by restart is the property this plan actually leans on.

Both directions were checked by injecting the defect rather than by trusting the green: forcing
log-only ON makes seven existing enforcement tests fail, and forcing it OFF makes T4 fail.

The certificate row deserved a note against the board, and the note is why it is now struck through.
`ENTERPRISE.md` gave axis 10 the trigger "any deployment that outlives its first certificate", which
reads like a late problem. Laid against this sequence it is not: an OPC UA deployment acquires
certificates in phase 4, so **the trigger fires inside the rollout, not after it** — which is what
made building the half that needs no CA the right next thing rather than a nicety.

What was built is the half §6 of that document had already fixed the order for: *decide the
disconnected-renewal behaviour, then integrate.* The behaviour is decided and coded — an expired
certificate is diagnosed and the edge does not stop — and offline key rotation needs no authority to
reach. **The integration itself is still deferred**, and the trigger for it is unchanged: a GDS or an
enterprise PKI, on the day a fleet makes manual renewal unworkable.

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
  an artifact worth having on its own.
- **What phases 4–6 now depend on has changed in kind.** The gap table above no longer has a
  *not built* row; every remaining item is half-built, and in each case **the missing half is the
  one this repository cannot build.** The vendor comparison has no live product to fetch from; the
  certificate work has no CA to enrol against; the Huginn seam has no protocol the two tools share;
  and write-path exclusivity ends at the plant's own server configuration. Those are not a backlog
  that more code closes — they are the boundary where a reference implementation stops and a
  deployment starts, which is the honest reading of how far this sequence can be taken on evidence
  from one machine.

---

*Duration figures: multi-site UNS experience
([Automation World](https://www.automationworld.com/factory/iiot/article/33016191/unified-namespace-real-world-applications-and-challenges)).
Conduit register expectations: see [`ENTERPRISE.md` §5](ENTERPRISE.md#5-conduit-inventory) for sources.*
