package dev.krillin.bifrost.core.conformance;
import static org.junit.jupiter.api.Assertions.*;
import java.util.List;
import dev.krillin.bifrost.core.schema.*;
import org.junit.jupiter.api.Test;

class TemplateConformanceCheckerTest {
    static UdtDefinition template() {
        return new UdtDefinition("WeldController-corp", SemVer.parse("1.0.0"), List.of(
            new Member("WeldCurrent","Double","corp:weld/current", new Range(0,15)),
            new Member("WeldTime","Double","corp:weld/time", new Range(0,600)),
            new Member("ElectrodeForce","Double","corp:weld/force", new Range(0,8))), List.of(), null);
    }
    static Member m(String n,String t,String sem,Range r){ return new Member(n,t,sem,r); }
    // full 3-member site varying only WeldCurrent (helpers):
    static UdtDefinition withCurrent(Range curRange) {
        return new UdtDefinition("Ulsan-Weld", SemVer.parse("1.0.0"), List.of(
            m("WeldCurrent","Double","corp:weld/current", curRange),
            m("WeldTime","Double","corp:weld/time", new Range(0,500)),
            m("ElectrodeForce","Double","corp:weld/force", new Range(0,6))), List.of(), "WeldController-corp@1.0.0");
    }
    static UdtDefinition withCurrentType(String type) {
        return new UdtDefinition("Ulsan-Weld", SemVer.parse("1.0.0"), List.of(
            m("WeldCurrent",type,"corp:weld/current", new Range(0,12)),
            m("WeldTime","Double","corp:weld/time", new Range(0,500)),
            m("ElectrodeForce","Double","corp:weld/force", new Range(0,6))), List.of(), "WeldController-corp@1.0.0");
    }
    TemplateConformanceChecker chk = new TemplateConformanceChecker();

    @Test void conformingSiteTightenedAndExtended() {
        UdtDefinition site = new UdtDefinition("Ulsan-Weld", SemVer.parse("1.0.0"), List.of(
            m("WeldCurrent","Double","corp:weld/current", new Range(0,12)),
            m("WeldTime","Double","corp:weld/time", new Range(0,500)),
            m("ElectrodeForce","Double","corp:weld/force", new Range(0,6)),
            m("WeldVoltage","Double","ulsan:weld/voltage", new Range(0,20))), List.of(), "WeldController-corp@1.0.0");
        assertTrue(chk.check(site, template()).ok());
    }
    @Test void exceedsEnvelopeRejected() {
        var v = chk.check(withCurrent(new Range(0,20)), template());
        assertFalse(v.ok());
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("template.range.exceeds-envelope")));
    }
    @Test void missingRequiredMemberRejected() {
        UdtDefinition site = new UdtDefinition("Ulsan-Weld", SemVer.parse("1.0.0"), List.of(
            m("WeldCurrent","Double","corp:weld/current", new Range(0,12)),
            m("ElectrodeForce","Double","corp:weld/force", new Range(0,6))), List.of(), "WeldController-corp@1.0.0");
        var v = chk.check(site, template());
        assertFalse(v.ok());
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("template.member.missing")));
    }
    @Test void semanticIdMismatchRejected() {
        UdtDefinition site = new UdtDefinition("Ulsan-Weld", SemVer.parse("1.0.0"), List.of(
            m("WeldCurrent","Double","ulsan:current", new Range(0,12)),
            m("WeldTime","Double","corp:weld/time", new Range(0,500)),
            m("ElectrodeForce","Double","corp:weld/force", new Range(0,6))), List.of(), "WeldController-corp@1.0.0");
        assertTrue(chk.check(site, template()).violations().stream().anyMatch(x -> x.rule().equals("template.semanticId.mismatch")));
    }
    @Test void typeMismatchRejected() {
        assertTrue(chk.check(withCurrentType("Float"), template()).violations().stream().anyMatch(x -> x.rule().equals("template.type.mismatch")));
    }
}
