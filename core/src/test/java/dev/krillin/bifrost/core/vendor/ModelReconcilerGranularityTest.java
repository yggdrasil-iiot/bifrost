package dev.krillin.bifrost.core.vendor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import dev.krillin.bifrost.core.schema.Member;
import dev.krillin.bifrost.core.schema.Range;
import dev.krillin.bifrost.core.schema.SemVer;
import dev.krillin.bifrost.core.schema.UdtDefinition;
import dev.krillin.bifrost.core.schema.Violation;

/**
 * Granularity is a property of the PRODUCT, not of the export.
 *
 * <p>The same JSON could come from a product with a per-object write API or from one whose only
 * ingest path is a whole entity blob, so it is declared on the source and travels into the verdict
 * untouched by the data. That is the reason the port exists at all: two booleans would report
 * Kepware, Ignition and ThingWorx as equally supported and hide the only difference an operator
 * plans around.
 *
 * <p>These tests also pin the refinement building this surfaced. {@code ENTERPRISE.md} §13 said the
 * smallest unit of both the finding and the fix is larger for a blob product. Half right: the fetch
 * and the fix are, but once the blob is parsed the finding is still per member -- so the verdict
 * carries the remediation unit separately instead of degrading the diagnosis to match it.
 */
class ModelReconcilerGranularityTest {

    private static UdtDefinition def(Member... members) {
        return new UdtDefinition("WeldController-corp", SemVer.parse("1.0.0"),
                List.of(members), List.of(), null);
    }

    private static final Member GOVERNED =
            new Member("WeldCurrent", "Double", "corp:weld/current", new Range(0.0, 15.0));
    private static final Member DRIFTED =
            new Member("WeldCurrent", "Int32", "corp:weld/current", new Range(0.0, 15.0));

    private static List<String> rules(ReconciliationVerdict v) {
        return v.findings().stream().map(Violation::rule).toList();
    }

    /** The findings come from the data; only the remediation unit comes from the product. */
    @Test void the_same_divergence_yields_the_same_findings_under_either_granularity() {
        ModelReconciler r = new ModelReconciler();
        ReconciliationVerdict perObject = r.reconcile(def(GOVERNED), def(DRIFTED), Granularity.PER_OBJECT);
        ReconciliationVerdict wholeSet = r.reconcile(def(GOVERNED), def(DRIFTED), Granularity.WHOLE_SET);

        assertEquals(rules(perObject), rules(wholeSet));
        assertEquals(perObject.findings(), wholeSet.findings());
        assertFalse(perObject.agreed());
        assertFalse(wholeSet.agreed());
    }

    @Test void the_remediation_unit_is_the_one_the_source_declared() {
        ModelReconciler r = new ModelReconciler();
        assertEquals(Granularity.PER_OBJECT,
                r.reconcile(def(GOVERNED), def(DRIFTED), Granularity.PER_OBJECT).remediationUnit());
        assertEquals(Granularity.WHOLE_SET,
                r.reconcile(def(GOVERNED), def(DRIFTED), Granularity.WHOLE_SET).remediationUnit());
    }

    /** A blob product's findings stay per member: the coarse thing is the fix, not the diagnosis. */
    @Test void a_whole_set_verdict_still_names_the_member() {
        ReconciliationVerdict v = new ModelReconciler()
                .reconcile(def(GOVERNED), def(DRIFTED), Granularity.WHOLE_SET);
        assertEquals(1, v.findings().size());
        assertTrue(v.findings().get(0).detail().contains("WeldCurrent"), v.findings().get(0).detail());
    }

    /** Carried even on agreement, so a caller can report it without a special case. */
    @Test void an_agreed_verdict_still_carries_the_remediation_unit() {
        ReconciliationVerdict v = new ModelReconciler()
                .reconcile(def(GOVERNED), def(GOVERNED), Granularity.WHOLE_SET);
        assertTrue(v.agreed());
        assertEquals(Granularity.WHOLE_SET, v.remediationUnit());
    }
}
