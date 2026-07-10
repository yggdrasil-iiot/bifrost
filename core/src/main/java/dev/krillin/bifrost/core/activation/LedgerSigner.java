package dev.krillin.bifrost.core.activation;

import dev.krillin.bifrost.core.schema.Violation;
import java.util.List;

/** The writer's signing seam (nullable in ActivationLedger.append / ActivationService.activate — null =
 *  exact T4 unsigned behavior). preflight() runs the fail-closed identity checks (key-file↔principal
 *  binding and cryptographic four-eyes) and returns them as Violations so ActivationService reports them
 *  exactly like T3's string SoD. sign()/signHead() produce the entry and head signatures. */
public interface LedgerSigner {
    List<Violation> preflight();
    Signatures sign(String entryHash);
    String signHead(String headPreimage);
    String approverPrincipal();
}
