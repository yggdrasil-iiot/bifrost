package dev.krillin.bifrost.core.schema;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Master-spec conformance rule engine (policy-as-code): checks that a {@link MasterSpec}'s setpoints
 * are admissible against the equipment {@link UdtDefinition} they target — {@code master spec ⊨ equipment model}.
 * Pure function, no I/O. Per setpoint: structural (member exists), type (matches member type), and
 * range (within the member's inclusive bounds; skipped when the member declares no range).
 */
public final class SpecConformanceChecker {

    public SpecVerdict check(UdtDefinition def, MasterSpec spec) {
        List<Violation> v = new ArrayList<>();
        Map<String, Member> members = byName(def.members());

        for (Setpoint s : spec.setpoints()) {
            Member m = members.get(s.member());

            // structural: an unknown member can be neither type- nor range-checked.
            if (m == null) {
                v.add(new Violation("spec.member.unknown",
                        "setpoint targets member '" + s.member() + "' which is absent from equipment '"
                                + def.templateRef() + "'"));
                continue;
            }

            // type: setpoint type must match the member's declared type.
            if (!m.type().equals(s.type())) {
                v.add(new Violation("spec.type.mismatch",
                        "member '" + s.member() + "' type mismatch — model declares " + m.type()
                                + " but setpoint is " + s.type()));
            }

            // range: bounded only when the member declares a range (null range ⇒ any numeric value allowed).
            if (m.range() != null) {
                if (s.value() < m.range().low()) {
                    v.add(new Violation("spec.range.below-min",
                            "member '" + s.member() + "' value " + s.value() + " is below min " + m.range().low()));
                }
                if (s.value() > m.range().high()) {
                    v.add(new Violation("spec.range.above-max",
                            "member '" + s.member() + "' value " + s.value() + " is above max " + m.range().high()));
                }
            }
        }

        return new SpecVerdict(v.isEmpty(), List.copyOf(v));
    }

    private Map<String, Member> byName(List<Member> members) {
        Map<String, Member> m = new LinkedHashMap<>();
        for (Member x : members) m.put(x.name(), x);
        return m;
    }
}
