package dev.krillin.bifrost.core.activation;

import java.io.IOException;
import java.util.Optional;

/** The monotonic external-anchor witness port (ports & adapters — the core stays anchor-agnostic,
 *  mirroring T1's standard-agnostic core). Contract:
 *   - append-only, monotonic NON-DECREASING: record(r) throws on r.seq() < latest.seq() (regression)
 *     and on a same-seq / different-tail conflict; a byte-identical same-(seq,tailEntryHash) record is
 *     an idempotent no-op (safe crash-retry re-anchor).
 *   - latest(target) returns the highest recorded record, or empty if the target was never anchored. */
public interface AnchorStore {
    Optional<AnchorRecord> latest(String target) throws IOException;
    void record(AnchorRecord r) throws IOException;
}
