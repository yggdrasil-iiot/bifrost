package dev.krillin.bifrost.core.schema;

import static org.junit.jupiter.api.Assertions.*;
import java.util.List;
import org.junit.jupiter.api.Test;

class SpecConformanceCheckerTest {

    private final SpecConformanceChecker checker = new SpecConformanceChecker();

    /** Mixer equipment model: Rpm [0,3000], Temp [0,450], Running Boolean (no range), Ratio Double (null range). */
    private final UdtDefinition mixer = new UdtDefinition("Mixer", SemVer.parse("1.0.0"),
            List.of(new Member("Rpm", "Double", null, new Range(0, 3000)),
                    new Member("Temp", "Double", null, new Range(0, 450)),
                    new Member("Running", "Boolean", null, null),
                    new Member("Ratio", "Double", null, null)),
            List.of(), null);

    private MasterSpec spec(List<Setpoint> setpoints) {
        return new MasterSpec("MixerRecipe", "1.0.0", "site-a", "Mixer", "1.0.0", setpoints);
    }

    @Test void conformant_spec_hasNoViolations() {
        SpecVerdict v = checker.check(mixer, spec(List.of(
                new Setpoint("Rpm", "Double", 1500),
                new Setpoint("Temp", "Double", 200))));
        assertTrue(v.conformant(), v.violations().toString());
        assertTrue(v.violations().isEmpty());
    }

    @Test void unknownMember_isStructuralViolation() {
        SpecVerdict v = checker.check(mixer, spec(List.of(new Setpoint("Ghost", "Double", 1))));
        assertFalse(v.conformant());
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("spec.member.unknown")));
    }

    @Test void typeMismatch_isViolation() {
        SpecVerdict v = checker.check(mixer, spec(List.of(new Setpoint("Rpm", "Int32", 1500))));
        assertFalse(v.conformant());
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("spec.type.mismatch")));
    }

    @Test void rangeAboveMax_isViolation() {
        SpecVerdict v = checker.check(mixer, spec(List.of(new Setpoint("Rpm", "Double", 9999))));
        assertFalse(v.conformant());
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("spec.range.above-max")));
    }

    @Test void rangeBelowMin_isViolation() {
        SpecVerdict v = checker.check(mixer, spec(List.of(new Setpoint("Temp", "Double", -5))));
        assertFalse(v.conformant());
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("spec.range.below-min")));
    }

    @Test void nullRangeMember_allowsAnyNumericValue() {
        // Ratio is a Double member with null range: any numeric value is accepted, no range check.
        SpecVerdict v = checker.check(mixer, spec(List.of(new Setpoint("Ratio", "Double", 99999))));
        assertTrue(v.conformant(), v.violations().toString());
        assertTrue(v.violations().stream().noneMatch(x -> x.rule().startsWith("spec.range")));
    }

    @Test void singleSetpoint_accumulatesTypeAndRange_noShortCircuit() {
        // One setpoint wrong on BOTH axes: Rpm is Double range [0,3000], setpoint is Int32 9999.
        // A wrong-type value is still range-checked — deliberate no-short-circuit design.
        SpecVerdict v = checker.check(mixer, spec(List.of(new Setpoint("Rpm", "Int32", 9999))));
        assertFalse(v.conformant());
        assertEquals(2, v.violations().size(), v.violations().toString());
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("spec.type.mismatch")));
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("spec.range.above-max")));
    }

    @Test void emptySetpoints_isVacuouslyConformant() {
        SpecVerdict v = checker.check(mixer, spec(List.of()));
        assertTrue(v.conformant());
        assertTrue(v.violations().isEmpty());
    }
}
