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
}
