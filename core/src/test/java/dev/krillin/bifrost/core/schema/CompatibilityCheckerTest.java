package dev.krillin.bifrost.core.schema;

import static org.junit.jupiter.api.Assertions.*;
import java.util.List;
import org.junit.jupiter.api.Test;

class CompatibilityCheckerTest {

    private final CompatibilityChecker checker = new CompatibilityChecker();

    private UdtDefinition motor(String version, List<Member> members) {
        return new UdtDefinition("Motor", SemVer.parse(version), members, List.of(), null);
    }

    private final List<Member> v1 = List.of(new Member("Rpm", "Double", null, null), new Member("Running", "Boolean", null, null));

    @Test void forward_addMember_isCompatible() {
        UdtDefinition reg = motor("1.0.0", v1);
        UdtDefinition pro = motor("1.1.0", List.of(new Member("Rpm", "Double", null, null),
                new Member("Running", "Boolean", null, null), new Member("Temperature", "Double", null, null)));
        Verdict v = checker.check(reg, pro, CompatMode.FORWARD);
        assertTrue(v.compatible(), v.violations().toString());
    }

    @Test void forward_removeMember_isIncompatible() {
        UdtDefinition reg = motor("1.0.0", v1);
        UdtDefinition pro = motor("1.1.0", List.of(new Member("Rpm", "Double", null, null)));
        Verdict v = checker.check(reg, pro, CompatMode.FORWARD);
        assertFalse(v.compatible());
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("member.removed")));
    }

    @Test void backward_addMember_isIncompatible() {
        UdtDefinition reg = motor("1.0.0", v1);
        UdtDefinition pro = motor("1.1.0", List.of(new Member("Rpm", "Double", null, null),
                new Member("Running", "Boolean", null, null), new Member("Temperature", "Double", null, null)));
        Verdict v = checker.check(reg, pro, CompatMode.BACKWARD);
        assertFalse(v.compatible());
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("member.added")));
    }

    @Test void backward_removeMember_isCompatible() {
        UdtDefinition reg = motor("1.0.0", v1);
        UdtDefinition pro = motor("1.1.0", List.of(new Member("Rpm", "Double", null, null)));
        Verdict v = checker.check(reg, pro, CompatMode.BACKWARD);
        assertTrue(v.compatible(), v.violations().toString());
    }

    @Test void typeChange_isIncompatible_inEveryModeButNone() {
        UdtDefinition reg = motor("1.0.0", v1);
        UdtDefinition pro = motor("1.1.0", List.of(new Member("Rpm", "Int32", null, null),
                new Member("Running", "Boolean", null, null)));
        for (CompatMode mode : List.of(CompatMode.FORWARD, CompatMode.BACKWARD, CompatMode.FULL)) {
            Verdict v = checker.check(reg, pro, mode);
            assertFalse(v.compatible(), "mode=" + mode);
            assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("member.typeChanged")), "mode=" + mode);
        }
    }

    @Test void none_skipsAllChecks() {
        UdtDefinition reg = motor("1.0.0", v1);
        UdtDefinition pro = motor("1.1.0", List.of(new Member("Rpm", "Int32", null, null))); // remove + type change
        Verdict v = checker.check(reg, pro, CompatMode.NONE);
        assertTrue(v.compatible(), v.violations().toString());
    }

    @Test void nonMonotonicVersion_isViolation() {
        UdtDefinition reg = motor("1.1.0", v1);
        UdtDefinition pro = motor("1.1.0", v1); // same version = violation
        Verdict v = checker.check(reg, pro, CompatMode.FORWARD);
        assertFalse(v.compatible());
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("version.monotonic")));
    }

    @Test void paramChange_classifiedLikeMembers() {
        UdtDefinition reg = new UdtDefinition("Motor", SemVer.parse("1.0.0"), v1, List.of(new Param("Location", "String")), null);
        UdtDefinition pro = new UdtDefinition("Motor", SemVer.parse("1.1.0"), v1, List.of(), null); // param removed
        Verdict v = checker.check(reg, pro, CompatMode.FORWARD);
        assertFalse(v.compatible());
        assertTrue(v.violations().stream().anyMatch(x -> x.rule().equals("param.removed")));
    }
}
