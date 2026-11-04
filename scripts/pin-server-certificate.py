"""Point a copy of the vor-read bundle's command links at OPC UA server certificates, and re-pin every digest.

The fixture names a certificate minted for the unit tests; the gates' sim mints a new one at every start. The gates
therefore copy the fixture, run this with the certificates the live sims exported, and publish the copy.

    python scripts/pin-server-certificate.py <bundle> <cert.der> [<cert.der> ...] [--application-uri URI] [--thumbprint HEX]
    python scripts/pin-server-certificate.py <bundle> --legacy

Each certificate becomes an evidence artifact server-certificate-<n> (application/pkix-cert), and both links'
endpointRef lists them all, in order (more than one is a rotation overlap). The thumbprint is the DER's SHA-1.
--application-uri overrides the link's applicationUri (default: the fixture's), for the publish check's refusal.
--thumbprint overrides every listed thumbprint, likewise.
--legacy writes the bundle as contract 2.25.0 did: links without endpointRef and no certificate artifact.
"""
import hashlib
import json
import sys
from pathlib import Path

LINKS = ("command-bindings/mixer1-set-temperature.json", "command-bindings/mixer2-set-temperature.json")
PREFIX = "server-certificate-"


def main(argv):
    root = Path(argv[0])
    rest = argv[1:]
    legacy = "--legacy" in rest
    uri = None
    if "--application-uri" in rest:
        i = rest.index("--application-uri")
        uri = rest[i + 1]
        del rest[i:i + 2]
    thumb = None
    if "--thumbprint" in rest:
        i = rest.index("--thumbprint")
        thumb = rest[i + 1]
        del rest[i:i + 2]
    certs = [Path(a) for a in rest if not a.startswith("--")]
    if legacy == bool(certs):
        sys.exit("give certificates or --legacy, not both and not neither")

    load = lambda rel: json.loads((root / rel).read_bytes())
    dump = lambda rel, d: (root / rel).write_bytes((json.dumps(d, indent=2) + "\n").encode())
    sha = lambda rel: hashlib.sha256((root / rel).read_bytes()).hexdigest()

    prop = load("proposal.json")
    # Drop the certificate artifacts the bundle had, with their bytes.
    kept = []
    template = None
    for e in prop["files"]:
        if e["id"].startswith(PREFIX):
            ev = load(e["path"])
            template = template or ev
            (root / ev["file"]["path"]).unlink()
            (root / e["path"]).unlink()
        else:
            kept.append(e)
    prop["files"] = kept

    entries = []
    for n, cert in enumerate(certs):
        cid = PREFIX + ("sim" if n == 0 else "sim-%d" % (n + 1))
        der = cert.read_bytes()
        data, evidence = "data/%s.der" % cid, "evidence/%s.json" % cid
        (root / data).write_bytes(der)
        ev = dict(template) if template else {
            "kind": "evidence-artifact", "schemaVersion": "1.1.0", "id": None, "version": "1.0.0", "origin": "synthetic",
            "file": None, "capturedAt": "2026-11-05T00:00:00Z", "product": None, "scope": ["line1"]}
        ev["id"] = cid
        ev["file"] = {"path": data, "sha256": hashlib.sha256(der).hexdigest(), "mediaType": "application/pkix-cert"}
        dump(evidence, ev)
        # after the last evidence artifact, where the fixture lists it
        at = max(i for i, e in enumerate(prop["files"]) if e["kind"] == "evidence-artifact") + 1
        prop["files"].insert(at, {"path": evidence, "kind": "evidence-artifact", "id": cid, "version": "1.0.0", "sha256": ""})
        entries.append({"thumbprintSha1": thumb or hashlib.sha1(der).hexdigest(), "certificateRef": {"id": cid, "version": "1.0.0"}})

    for rel in LINKS:
        d = load(rel)
        if legacy:
            d["schemaVersion"] = "2.25.0"
            d.pop("endpointRef", None)
        else:
            d["schemaVersion"] = "2.26.0"
            old = d.get("endpointRef", {"applicationUri": "urn:bifrost:opcua:sim-server"})
            ref = {"applicationUri": uri or old["applicationUri"], "certificates": entries}
            d = {k: v for k, v in d.items() if k != "endpointRef"}
            out = {}
            for k, v in d.items():
                out[k] = v
                if k == "method":
                    out["endpointRef"] = ref
            d = out
        dump(rel, d)

    prop["schemaVersion"] = "2.25.0" if legacy else "2.26.0"
    for e in prop["files"]:
        e["sha256"] = sha(e["path"])
    dump("proposal.json", prop)
    s = load("submission.json")
    s["proposalSha256"] = s["workspaceSha256"] = sha("proposal.json")
    dump("submission.json", s)
    for e in entries:
        print(e["thumbprintSha1"])


if __name__ == "__main__":
    main(sys.argv[1:])
