package dev.krillin.bifrost.core.conformance;
import static org.junit.jupiter.api.Assertions.*;
import java.util.List;
import dev.krillin.bifrost.core.schema.*;
import org.junit.jupiter.api.Test;

class ConformanceEvaluatorTest {
    static UdtDefinition weld() {
        return new UdtDefinition("Weld-Controller", SemVer.parse("1.0.0"), List.of(
            new Member("WeldCurrent","Double",null,new Range(0,12)),
            new Member("WeldTime","Double",null,new Range(0,500)),
            new Member("ElectrodeForce","Double",null,new Range(0,6))), List.of(), null);
    }
    static ConformancePolicy lobe(String mode, String rRef, String rVer, Double tol) {
        return new ConformancePolicy("WeldPolicy","1.0.0","Weld-Controller","1.0.0",
            new ConformancePolicy.Dial(mode, rRef, rVer, tol),
            List.of(new CrossConstraint("weld-lobe","ElectrodeForce","lt",3.0,"WeldCurrent","le",8.0)),
            List.of());
    }
    static MasterSpec masterSpec(String member, double value) {
        return new MasterSpec("WeldSchedule","1.0.0","BodyShop","Weld-Controller","1.0.0",
            List.of(new Setpoint(member,"Double",value)));
    }
    ConformanceEvaluator ev = new ConformanceEvaluator();

    @Test void envelopePassesButCrossMemberDenies() {  // THE composition case
        var v = ev.evaluate(weld(), lobe("envelope",null,null,null), null, List.of(
            new Setpoint("WeldCurrent","Double",9.0), new Setpoint("ElectrodeForce","Double",2.5)));
        assertFalse(v.ok());
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("conformance.cross.weld-lobe")));
    }
    @Test void withinLobeAndEnvelopePasses() {
        var v = ev.evaluate(weld(), lobe("envelope",null,null,null), null, List.of(
            new Setpoint("WeldCurrent","Double",7.0), new Setpoint("ElectrodeForce","Double",2.5)));
        assertTrue(v.ok());
    }
    @Test void envelopeAboveMax() {
        var v = ev.evaluate(weld(), null, null, List.of(new Setpoint("WeldCurrent","Double",13.0)));
        assertFalse(v.ok());
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("spec.range.above-max")));
    }
    @Test void structuralUnknownMember() {
        var v = ev.evaluate(weld(), null, null, List.of(new Setpoint("Ghost","Double",1.0)));
        assertFalse(v.ok());
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("spec.member.unknown")));
    }
    @Test void gracefulDegradeNoPolicy() {  // structural+type+envelope only == old SpecConformanceChecker
        var v = ev.evaluate(weld(), null, null, List.of(new Setpoint("WeldCurrent","Double",7.0)));
        assertTrue(v.ok());
    }
    @Test void recipeModeDeviationDenies() {
        MasterSpec recipe = masterSpec("WeldCurrent", 9.0);  // approved schedule 9kA
        var v = ev.evaluate(weld(), lobe("recipe","WeldSchedule","1.0.0",0.0), recipe, List.of(
            new Setpoint("WeldCurrent","Double",7.0), new Setpoint("ElectrodeForce","Double",4.0)));
        assertFalse(v.ok());
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("conformance.recipe.deviation")));
    }

    // --- parity cases ported from SpecConformanceCheckerTest (the evaluator now solely owns these) ---
    // model with a null-range member: ElectrodeForce-like siblings plus a rangeless Double member.
    static UdtDefinition weldWithRatio() {
        return new UdtDefinition("Weld-Controller", SemVer.parse("1.0.0"), List.of(
            new Member("WeldCurrent","Double",null,new Range(0,12)),
            new Member("WeldTime","Double",null,new Range(0,500)),
            new Member("ElectrodeForce","Double",null,new Range(0,6)),
            new Member("Ratio","Double",null,null)), List.of(), null);
    }

    @Test void typeMismatchDenies() {
        var v = ev.evaluate(weld(), null, null, List.of(new Setpoint("WeldCurrent","Int32",7.0)));
        assertFalse(v.ok());
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("spec.type.mismatch")));
    }
    @Test void envelopeBelowMin() {
        var v = ev.evaluate(weld(), null, null, List.of(new Setpoint("WeldCurrent","Double",-5.0)));
        assertFalse(v.ok());
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("spec.range.below-min")));
    }
    @Test void nullRangeMemberAllowsAnyValue() {
        var v = ev.evaluate(weldWithRatio(), null, null, List.of(new Setpoint("Ratio","Double",99999)));
        assertTrue(v.ok(), v.violations().toString());
        assertTrue(v.violations().stream().noneMatch(x -> x.rule().startsWith("spec.range")));
    }
    @Test void typeAndRangeAccumulateNoShortCircuit() {
        // wrong on BOTH axes: Int32 type + 9999 above WeldCurrent max 12 -> two violations, no short-circuit.
        var v = ev.evaluate(weld(), null, null, List.of(new Setpoint("WeldCurrent","Int32",9999)));
        assertFalse(v.ok());
        assertEquals(2, v.violations().size(), v.violations().toString());
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("spec.type.mismatch")));
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("spec.range.above-max")));
    }
    @Test void emptyStateIsVacuouslyConformant() {
        var v = ev.evaluate(weld(), null, null, List.of());
        assertTrue(v.ok());
        assertTrue(v.violations().isEmpty());
    }

    // --- cross-member antecedent semantics ---
    @Test void crossVacuousWhenAntecedentFalse() {
        // ElectrodeForce=4.0 is NOT < 3 -> antecedent false -> constraint vacuously satisfied even at WeldCurrent max.
        var v = ev.evaluate(weld(), lobe("envelope",null,null,null), null, List.of(
            new Setpoint("WeldCurrent","Double",12.0), new Setpoint("ElectrodeForce","Double",4.0)));
        assertTrue(v.ok(), v.violations().toString());
        assertTrue(v.violations().stream().noneMatch(x -> x.rule().startsWith("conformance.cross")));
    }
    @Test void crossFailClosedWhenConsequentAbsent() {
        // antecedent holds (ElectrodeForce=2.5 < 3) but WeldCurrent absent -> FAIL-CLOSED.
        var v = ev.evaluate(weld(), lobe("envelope",null,null,null), null, List.of(
            new Setpoint("ElectrodeForce","Double",2.5)));
        assertFalse(v.ok());
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("conformance.cross.weld-lobe")));
    }
}
