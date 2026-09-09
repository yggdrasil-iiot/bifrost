package dev.krillin.bifrost.core.vendor;

import java.util.List;

import dev.krillin.bifrost.core.schema.Violation;

/**
 * The result of comparing a governed definition against a vendor's copy of it.
 *
 * <p>{@code remediationUnit} is carried SEPARATELY from the findings on purpose. For a whole-set
 * product the fetch and the fix are coarse, but once the export is parsed the finding is still per
 * member -- and keeping that detail is strictly better for whoever has to act on it. Degrading the
 * diagnosis to match the fix would throw away information the operator already has.
 *
 * <p>Findings reuse {@link Violation} rather than a parallel vocabulary, because a divergence is
 * the same shape of fact as a compatibility violation: a rule id and a human-readable explanation.
 *
 * <p><b>Agreement is not correctness.</b> A finding proves the two copies disagree; it does not say
 * which one is right. The governed side is the declared intent, and deciding that the vendor's copy
 * is the mistake is a human act with an owner.
 */
public record ReconciliationVerdict(boolean agreed, Granularity remediationUnit,
                                    List<Violation> findings) {

    public ReconciliationVerdict {
        findings = List.copyOf(findings);
    }
}
