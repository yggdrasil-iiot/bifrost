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
 * Comparing the governed definition against the vendor's copy of it.
 *
 * <p>Both sides are canonical {@link UdtDefinition}s by the time they get here: the vendor's export
 * has already been normalized through the existing {@code TemplateAdapter}. That reuse is the whole
 * design -- the anti-corruption layer built for the inbound direction serves the outbound one, so
 * {@code core} gains no new vendor knowledge.
 *
 * <p>A finding proves the two copies <b>disagree</b>. It does not prove which is right; the
 * governed side is the declared intent, and deciding the vendor's copy is the mistake is a human
 * act with an owner.
 */
class ModelReconcilerTest {

    private static UdtDefinition def(Member... members) {
        return new UdtDefinition("WeldController-corp", SemVer.parse("1.0.0"),
                List.of(members), List.of(), null);
    }

    private static Member m(String name, String type, String semanticId, Double low, Double high) {
        return new Member(name, type, semanticId, low == null ? null : new Range(low, high));
    }

    private static Member current() {
        return m("WeldCurrent", "Double", "corp:weld/current", 0.0, 15.0);
    }

    private static Member time() {
        return m("WeldTime", "Double", "corp:weld/time", 0.0, 600.0);
    }

    private static ReconciliationVerdict reconcile(UdtDefinition governed, UdtDefinition vendor) {
        return new ModelReconciler().reconcile(governed, vendor, Granularity.PER_OBJECT);
    }

    private static List<String> rules(ReconciliationVerdict v) {
        return v.findings().stream().map(Violation::rule).toList();
    }

    // ----- agreement -----

    @Test void an_identical_pair_agrees() {
        ReconciliationVerdict v = reconcile(def(current(), time()), def(current(), time()));
        assertTrue(v.agreed(), String.valueOf(v.findings()));
        assertEquals(List.of(), v.findings());
    }

    /** Order is a serialization accident, not a divergence. */
    @Test void member_order_does_not_matter() {
        ReconciliationVerdict v = reconcile(def(current(), time()), def(time(), current()));
        assertTrue(v.agreed(), String.valueOf(v.findings()));
    }

    // ----- one finding each, on the exact rule string -----

    @Test void a_member_the_vendor_lacks_is_missing() {
        ReconciliationVerdict v = reconcile(def(current(), time()), def(current()));
        assertFalse(v.agreed());
        assertEquals(List.of("vendor.member.missing"), rules(v));
        assertTrue(v.findings().get(0).detail().contains("WeldTime"), v.findings().get(0).detail());
    }

    @Test void a_member_only_the_vendor_has_is_unexpected() {
        ReconciliationVerdict v = reconcile(def(current()), def(current(), time()));
        assertFalse(v.agreed());
        assertEquals(List.of("vendor.member.unexpected"), rules(v));
        assertTrue(v.findings().get(0).detail().contains("WeldTime"));
    }

    @Test void a_retyped_member_is_a_type_mismatch() {
        ReconciliationVerdict v = reconcile(def(current()),
                def(m("WeldCurrent", "Int32", "corp:weld/current", 0.0, 15.0)));
        assertEquals(List.of("vendor.member.type-mismatch"), rules(v));
        assertTrue(v.findings().get(0).detail().contains("Double"), v.findings().get(0).detail());
        assertTrue(v.findings().get(0).detail().contains("Int32"));
    }

    @Test void a_widened_range_is_a_range_mismatch() {
        ReconciliationVerdict v = reconcile(def(time()),
                def(m("WeldTime", "Double", "corp:weld/time", 0.0, 900.0)));
        assertEquals(List.of("vendor.member.range-mismatch"), rules(v));
    }

    /** One side null is still a divergence -- a dropped range is how a bound silently disappears. */
    @Test void a_range_present_on_one_side_only_is_a_mismatch() {
        ReconciliationVerdict v = reconcile(def(time()),
                def(m("WeldTime", "Double", "corp:weld/time", null, null)));
        assertEquals(List.of("vendor.member.range-mismatch"), rules(v));
    }

    @Test void a_repointed_semantic_id_is_a_mismatch() {
        ReconciliationVerdict v = reconcile(def(current()),
                def(m("WeldCurrent", "Double", "corp:weld/amperage", 0.0, 15.0)));
        assertEquals(List.of("vendor.member.semantic-id-mismatch"), rules(v));
    }

    @Test void a_semantic_id_present_on_one_side_only_is_a_mismatch() {
        ReconciliationVerdict v = reconcile(def(current()),
                def(m("WeldCurrent", "Double", null, 0.0, 15.0)));
        assertEquals(List.of("vendor.member.semantic-id-mismatch"), rules(v));
    }

    // ----- completeness of the report -----

    /** An operator fixing one divergence per round trip is a worse outcome than a list. */
    @Test void every_divergence_is_reported_not_just_the_first() {
        ReconciliationVerdict v = reconcile(
                def(current(), time(), m("ElectrodeForce", "Double", "corp:weld/force", 0.0, 8.0)),
                def(m("WeldCurrent", "Int32", "corp:weld/current", 0.0, 15.0),
                    m("CoolantTemp", "Double", "corp:cool/temp", 0.0, 90.0)));
        assertFalse(v.agreed());
        assertTrue(rules(v).contains("vendor.member.type-mismatch"), String.valueOf(rules(v)));
        assertTrue(rules(v).contains("vendor.member.missing"));
        assertTrue(rules(v).contains("vendor.member.unexpected"));
        assertEquals(2, rules(v).stream().filter("vendor.member.missing"::equals).count(),
                "both WeldTime and ElectrodeForce are absent from the vendor copy");
    }

    /** A member wrong in two ways yields two findings -- the report is not truncated per member. */
    @Test void two_faults_on_one_member_are_two_findings() {
        ReconciliationVerdict v = reconcile(def(current()),
                def(m("WeldCurrent", "Int32", "corp:weld/current", 0.0, 99.0)));
        assertEquals(2, v.findings().size(), String.valueOf(rules(v)));
        assertTrue(rules(v).contains("vendor.member.type-mismatch"));
        assertTrue(rules(v).contains("vendor.member.range-mismatch"));
    }

    /**
     * Pinned deliberately. {@code TemplateAdapter.adapt(external, ref, version)} takes the ref and
     * version as PARAMETERS -- its javadoc says the external document may not carry Bifrost's -- so
     * a templateRef or version finding would compare an operator's own argument against itself and
     * could never fire. That is the vacuous assertion R5's K6 turned out to be, caught this time
     * before it was written. This test exists so nobody "fixes" the omission later.
     */
    @Test void there_is_no_templateRef_or_version_finding() {
        UdtDefinition governed = new UdtDefinition("A", SemVer.parse("1.0.0"), List.of(current()),
                List.of(), null);
        UdtDefinition vendor = new UdtDefinition("B", SemVer.parse("9.9.9"), List.of(current()),
                List.of(), null);
        ReconciliationVerdict v = reconcile(governed, vendor);
        assertTrue(v.agreed(),
                "identity is an operator input, not something the export carries: " + v.findings());
    }
}
