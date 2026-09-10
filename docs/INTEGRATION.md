# Where your existing systems meet this

You already have a SCADA, a historian, an MES, and something doing PLC connectivity. The first
question anyone asks about this project is which of those it sits above, below, or replaces.

**The answer is none of them, and that is the design rather than a limitation.** This document is
the wire-level version of that answer: every boundary, which protocol crosses it, who initiates,
and who owns the thing on each side. It is written from the code — the topic strings, adapters and
CLI surfaces named below are the ones that exist, and the section at the end says which parts of
the picture are not built.

If you want the ISA-95 stack drawing, it is not here, because the honest picture is not a stack.

---

## The shortest form

| You have | It talks to Yggdrasil over | In which direction | It stays |
|---|---|---|---|
| **PLCs** | nothing — this project never speaks a PLC protocol | — | wherever it is |
| **Kepware / Ignition / any OPC-UA server** | **OPC-UA** | this project browses, reads and writes; the server is the authority on who may | bought, and in the path |
| **Historian** | **MQTT / Sparkplug B** | subscribes | bought, and downstream |
| **SCADA / HMI** | **MQTT / Sparkplug B**, *and* a model export file | subscribes; hands over its model copy for reconciliation | bought, and downstream |
| **MES** | **MQTT / Sparkplug B** | subscribes for data; publishes NCMD to command | bought, and downstream |
| **OT firewall / VLAN / NAC** | nothing — no integration | — | the plant's, and it enforces what this cannot |
| **Commercial OT monitor** (Claroty, Nozomi, Dragos, …) | nothing today — a declaration file it could consume | — | the plant's, and its protocol breadth exceeds Huginn's |

Two rows carry most of the surprise. **The MES is a peer of the historian, not a parent of this
project** — it subscribes like everything else, and when it commands, it is an authenticated
requester subject to the same deny-by-default rule as anything else that publishes an NCMD. And
**the vendor's OPC-UA server, not this project, is what makes the governed edge the exclusive
writer** ([`ENTERPRISE.md` §12](ENTERPRISE.md#12-write-path-exclusivity)).

---

## Containment: there isn't any

The instinct is to place this somewhere in a layer diagram. Resist it for one paragraph, because
the placement is what produces every wrong follow-up question.

There are two planes, and this project lives almost entirely in one of them.

- **The data plane** — PLC → OPC-UA server → edge → broker → consumers. This is the plane your MES,
  SCADA and historian already live on, and **this project adds exactly two components to it**:
  Muninn (the northbound feeder) and Heimdall (the write boundary). Both are replaceable; neither
  is privileged by the data plane itself.
- **The control plane** — a git registry that owns the canonical model, its versions, its
  conformance policy, its command authorization, and the ledger of which version is active where.
  **Nothing on the data plane owns any of that today**, which is the gap the project exists for.

So the containment question has an answer, but it is not the expected one: **the contract contains
the products, not the other way round.** A historian, an Ignition, a ThingWorx and an MES are all
consumers of one governed model that none of them owns. Replacing any of them is a subscriber
change. Replacing the model is a governance event with four-eyes approval and a ledger entry.

That inversion is the whole claim. Everything below is the mechanics of it.

---

## Every boundary, with the protocol on it

```
                    ┌──────────────── control plane (git) ───────────────┐
                    │  UdtDefinition · MasterSpec · ConformancePolicy     │
                    │  CommandPolicy · activation ledger · anchor         │
                    └───┬────────────────────────┬──────────────────┬─────┘
                   file │ (gates CLI, pre-deploy)│ read at startup  │ projection
                        ▼                        ▼                  ▼
   PLC ──native──▶ OPC-UA server ──OPC-UA──▶ Muninn ──Sparkplug──▶ broker ──▶ historian
 (S7, EtherNet/IP,  (Kepware,          (feed)                  (MQTT)    │      MES
  Modbus/TCP)        Ignition, …)                                        │      SCADA / HMI
                        ▲                                                │      cloud / AI
                        └────OPC-UA write──── Heimdall ◀────NCMD─────────┘
                                           (write boundary)

   SPAN / TAP ──pcap──▶ Huginn (observe)  ◀── CommunicationPolicy (projected from the registry)
```

| Boundary | Initiator | Protocol | Owned by |
|---|---|---|---|
| PLC → OPC-UA server | the server polls | PLC-native (S7, EtherNet/IP, Modbus/TCP) | **vendor** — Kepware, Ignition |
| OPC-UA server → Mímir | Mímir browses, design-time | **OPC-UA** (Eclipse Milo) | this project |
| OPC-UA server → Muninn | Muninn reads, runtime | **OPC-UA** (Eclipse Milo) | this project |
| Muninn → broker | Muninn publishes | **MQTT / Sparkplug B** (Eclipse Tahu + Paho) | this project |
| broker → consumers | the consumer subscribes | **MQTT / Sparkplug B** | **the consumer** — historian, MES, SCADA, cloud |
| consumer → Heimdall | the consumer publishes NCMD | **MQTT / Sparkplug B** | **the consumer** |
| Heimdall → OPC-UA server | Heimdall writes | **OPC-UA** (X.509 identity, opt-in) | this project |
| SPAN/TAP → Huginn | somebody hands over a pcap | **pcap** (Modbus/TCP, S7comm decoded) | the plant, then this project |
| registry → vendor product | a person carries a file | **file** — no live connection exists | see the gaps below |

**The direction of the broker connection is a security property, not an implementation detail.**
The edge dials *out* to the broker; no consumer ever opens a connection into the OT segment. An
MES that wants a setpoint changed publishes to a topic — it never routes into the plant.

---

## The actual topics

Verified against the code rather than a design note. `<group>` carries the ISA-95 hierarchy
(`Plant/Area/Line`), `<edge>` is the Sparkplug edge node id.

| Topic | Who publishes | Who subscribes | What it is |
|---|---|---|---|
| `spBv1.0/<group>/NBIRTH/<edge>` | **Muninn** | any consumer | the birth certificate, carrying the **byte-exact governed definition** as a `Bytes` metric |
| `spBv1.0/<group>/NDATA/<edge>` | **Muninn** (feed) · **Heimdall** (command response) | any consumer | egress-validated samples · correlated command outcomes |
| `spBv1.0/<group>/NCMD/<edge>` | **any consumer with a command to issue** — MES, SCADA, an operator tool | **Heimdall** | the write request, deny-by-default at the edge |
| `bifrost/<group>/QUERY/<edge>` | any consumer | **Heimdall** | a read-back request. **Not Sparkplug** — this project's own convention |
| `bifrost/<group>/STATUS/<edge>` | **Heimdall** | anyone watching the edge | retained `online`/`offline` liveness |

Two deliberate choices are worth reading, because they are the sort of thing a Sparkplug-literate
reviewer checks first.

**Heimdall does not birth the node, and its liveness topic is not `NDEATH`.** In the spine, Muninn
is the node that births this group/edge, and two components birthing one edge is a protocol error
rather than a detail. Deciding who owns the Sparkplug node identity for an edge that Heimdall
commands and Muninn feeds is a real open question; until it is answered, Heimdall announces itself
on its own topic rather than forging a second identity.

**Reads bypass authorization, on purpose and with a cost.** `handle()` short-circuits the QUERY
topic and `op=read` before the authorization check, so every claim about deny-by-default in this
project is a claim about **commands that write**. Read authorization is the broker's job, and see
the gaps below for why that half is projected rather than enforced.

---

## The systems, one at a time

### Kepware, Ignition, or whatever exposes OPC-UA

This is the only existing product that is **in the path** rather than downstream, and it holds two
jobs this project deliberately does not take.

- **Protocol breadth.** The long tail of PLC drivers is bought. Nothing here speaks S7 or
  EtherNet/IP, and adding that would be re-implementing a product that already works.
- **Write permission.** The lock that makes the governed edge the *exclusive* writer is ordinary
  OPC-UA server configuration — only the governed identity may write the controlled nodes, every
  other session read-only. This project supplies the key (`EdgeIdentity` mints an
  application-instance certificate and presents it on a `Basic256Sha256`/`SignAndEncrypt` endpoint,
  refusing to run at all if no such endpoint is offered). **The lock is the plant's.**

One thing it cannot do, and the asymmetry is the interesting part: **Kepware alone cannot
*publish* Sparkplug B.** Its IoT Gateway MQTT agent publishes JSON in bulk, with no per-tag topic
structure and no birth/death semantics — while its MQTT Client *driver* decodes Sparkplug B when
subscribing. So it can consume a UNS it cannot produce, and a Sparkplug publisher is a separate
component either way: Muninn here, or Ignition + Cirrus Link, or HiveMQ Edge elsewhere.

### SCADA / HMI

**This is the system with two relationships, and only one of them is obvious.**

1. **A subscriber.** It reads the UNS like anything else. Zero integration work; it connects to a
   broker.
2. **A holder of a copy of the governed model.** An Ignition UDT, a ThingWorx template, a Kepware
   tag list and a historian's tag set are all *copies* of the equipment model — and **whichever
   copy gets hand-edited is the real source of truth**, regardless of what the registry says.

`gates model-reconcile` addresses the second: it compares the vendor's exported model against the
governed definition and names divergence **per member**. Three `TemplateAdapter` implementations
(`IgnitionUdtAdapter`, `CfihosTemplateAdapter`, `AasSubmodelAdapter`) mean the enterprise template
does not have to be expressed in one vendor's dialect, and the port carries **granularity** so a
product that can only export a blob is recorded as weaker evidence than a per-object one.

Which product exposes what, and at which version, is in
[`ENTERPRISE.md` §13](ENTERPRISE.md#13-governed-model-vs-vendor-runtime). The short version: the
Ignition tag/UDT export endpoint does not exist before **8.3.2**, and parts of the Kepware
Configuration API need particular 6.x versions — which is why
[`ADOPTION.md` phase 0](ADOPTION.md#0--observe-only) collects product versions before anything else.

### Historian

A pure subscriber, and the source of the most common false finding in this system.

`gates conduit-project` emits the governed conduits as the `CommunicationPolicy` Huginn reads —
but it emits a **fragment** that says the governed edge is the only permitted **writer** of that
equipment. **Bifrost does not know which HMIs and historians may legitimately *read* it.** Run that
fragment alone and every legitimate historian is reported as a violation. It has to be merged into
the site policy, which means somebody has to write down the read side by hand.

### MES

The MES has no privileged position here, and that is the part that surprises people.

- **Reading** — it subscribes to Sparkplug like the historian. Nothing special.
- **Commanding** — a work order, a recipe download, a re-sequencing decision becomes an **NCMD
  publish**. At that moment the MES is a requester like any other, and Heimdall independently
  re-authorizes it at the edge *without trusting any upstream authorization*: the command ACL, the
  conformance bounds, and the governed active version all apply. A command outside the admissible
  range is refused at the edge even if the MES was entirely certain it was correct.

**Three limits on that, all real.** The requester's identity is verified only with
`REQUIRE_SIGNED_COMMAND` on, and that bar is **off by default**. Reads bypass it entirely. And
replay is refused from a bounded in-memory window that a bridge restart empties — durable freshness
needs a timestamp and a clock the site trusts, and OT sites frequently have neither.

For a worked example of a consumer on the other side of this contract — a Kotlin control
application that verifies a Bifrost-published provenance manifest with **zero Bifrost code on its
classpath** — see
[`resequence-twin-lab`](https://github.com/LivingLikeKrillin/resequence-twin-lab).

### The broker

Bought or OSS (HiveMQ, EMQX, Mosquitto). This project does not implement one, and re-implementing
the Sparkplug spec is likewise out of scope — Eclipse Tahu and Paho do it.

Broker-side UNS governance arrived independently while this was being built (EMQX Enterprise 6.2
enforces topic structure at ACL-check time and validates payload schemas at publish). That is a
genuine validation of the premise, and **a different axis**: it governs *data* at publish time,
this governs *control* at a pre-deploy gate plus re-authorization at the edge. The comparison is in
[`ENTERPRISE.md`](ENTERPRISE.md#where-this-sits-next-to-what-shipped).

### The network, and the things already watching it

**Enforcement is layered, and the last two layers are not this project's**
([`ENTERPRISE.md` §5](ENTERPRISE.md#5-conduit-inventory)). The OT firewall blocks by
`(src, dst, port)` — position, not meaning — which is the only answer available for a protocol
nobody decodes, S7comm-plus under TLS included. NAC / 802.1X stops an unregistered device from ever
joining the segment. Where a commercial passive monitor already exists, **its protocol breadth
exceeds Huginn's, and the declaration this project produces should feed it rather than compete with
it.**

Nothing in this sequence is meant to stand beside those. It is meant to stand on them.

---

## What is not built

The picture above is the design. These are the places where a reader who assumed it all works
would be wrong.

- **No live connection to any vendor product exists.** `model-reconcile` reads a
  `FileVendorModelSource` — the export arrives as a **file somebody hands over**. Nothing connects
  to a running Kepware, Ignition or ThingWorx.
- **The projection direction does not exist at all.** Nothing generates or pushes a vendor
  configuration *from* the governed model. Verification finds divergence; it does not prevent it.
  And a finding proves only that the two copies disagree — not which one is right.
- **The broker half is projected, not enforced.** `gates acl-project` emits the ACL a command
  policy implies (`principal → spBv1.0/<group>/NCMD/<edge>`, `PUBLISH`) as **a static artifact
  only**. No broker in this repository enforces it; the shared HiveMQ CE runs an allow-all
  extension deliberately.
- **There is no read-permission model anywhere.** Who may *subscribe* to what is unmodelled, which
  is why the conduit fragment cannot stand alone.
- **The command requester is only sometimes verified**, per the MES section above.
- **Nothing here has run in a plant.** Every gate runs against this repository's own sim and its
  own broker container. What transfers is the mechanism, not a deployment.

---

## Where to go next

- **[`ADOPTION.md`](ADOPTION.md)** — the order this goes into a plant that is already running, and
  the phase where it stops being risk-free. Phase 0 touches nothing and produces an artifact
  auditors already ask for.
- **[`ENTERPRISE.md`](ENTERPRISE.md)** — thirteen axes with *built · deferred · open · measured*
  status, including the two this document leans on hardest: §5 (the division of labour with the
  plant's own infrastructure) and §13 (the governed model against the vendor's copy).
- **The gates** — every claim above that is marked built is backed by a script in `scripts/` that
  exits `0` or does not pass.

---

*The topic strings, the read short-circuit, the ACL projection shape, the adapter names and the
vendor-source port are read out of this repository's code, not from a design note. The external
claims on this page: Kepware IoT Gateway publishes JSON rather than Sparkplug while the MQTT Client
driver decodes Sparkplug on subscribe
([PTC Community](https://community.ptc.com/t5/Kepware/Kepware-IOT-Gateway-and-UNS/td-p/1007506));
the Ignition and Kepware API findings and the broker-side UNS governance comparison carry their
sources in [`ENTERPRISE.md`](ENTERPRISE.md).*
