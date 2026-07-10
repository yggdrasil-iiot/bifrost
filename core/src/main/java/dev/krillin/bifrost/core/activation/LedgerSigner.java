package dev.krillin.bifrost.core.activation;

import dev.krillin.bifrost.core.schema.Violation;
import java.util.List;

/** The writer's signing seam (nullable in ActivationLedger.append / ActivationService.activate — null =
 *  exact T4 unsigned behavior). preflight() runs the fail-closed identity checks (key-file↔principal
 *  binding and cryptographic four-eyes) and returns them as Violations so ActivationService reports them
 *  exactly like T3's string SoD. sign()/signHead() produce the entry and head signatures.
 *  Lives in core.activation (with a concrete impl in core.identity) — the two packages are mutually
 *  dependent within this one Maven module; the seam keeps the ledger unaware of the key-file mechanics. */
public interface LedgerSigner {
    List<Violation> preflight();
    Signatures sign(String entryHash);
    String signHead(String headPreimage);
    /** The principal whose key signs the activator slot — must equal the event's activatedBy at write time. */
    String activatorPrincipal();
    /** The principal whose key signs the approver slot AND the head — must equal the event's approvedBy. */
    String approverPrincipal();
}
