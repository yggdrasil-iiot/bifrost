package dev.krillin.bifrost.core.schema;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * UDT data-contract compatibility rule engine (policy-as-code). Pure function, no I/O.
 * Semantics: FORWARD = add OK / remove or type-change = violation;
 *            BACKWARD = remove OK / add or type-change = violation;
 *            FULL = add, remove, and type-change all violate;
 *            NONE = no checks.
 */
public final class CompatibilityChecker {

    public Verdict check(UdtDefinition registered, UdtDefinition proposed, CompatMode mode) {
        List<Violation> v = new ArrayList<>();

        if (proposed.version().compareTo(registered.version()) <= 0) {
            v.add(new Violation("version.monotonic",
                    "proposed version " + proposed.version() + " is not greater than registered version " + registered.version()));
        }

        if (mode != CompatMode.NONE) {
            classify(types(registered.members()), types(proposed.members()), mode, v, "member");
            classify(paramTypes(registered.params()), paramTypes(proposed.params()), mode, v, "param");
        }

        return new Verdict(mode, v.isEmpty(), List.copyOf(v));
    }

    /** Classifies additions, removals, and type changes as violations according to the active mode. */
    private void classify(Map<String, String> reg, Map<String, String> pro,
                          CompatMode mode, List<Violation> v, String kind) {
        boolean addBreaks    = mode == CompatMode.BACKWARD || mode == CompatMode.FULL;
        boolean removeBreaks = mode == CompatMode.FORWARD  || mode == CompatMode.FULL;

        for (String name : pro.keySet()) {
            if (!reg.containsKey(name) && addBreaks) {
                v.add(new Violation(kind + ".added",
                        kind + " '" + name + "' added - violates " + mode + " (field absent in old data); new templateRef + major bump required"));
            }
        }
        for (Map.Entry<String, String> e : reg.entrySet()) {
            String name = e.getKey();
            if (!pro.containsKey(name)) {
                if (removeBreaks) {
                    v.add(new Violation(kind + ".removed",
                            kind + " '" + name + "' removed - violates " + mode + " (old consumers expect this field); new templateRef + major bump required"));
                }
            } else if (!pro.get(name).equals(e.getValue())) {
                v.add(new Violation(kind + ".typeChanged",
                        kind + " '" + name + "' type changed " + e.getValue() + " -> " + pro.get(name) + " - breaking in all modes"));
            }
        }
    }

    private Map<String, String> types(List<Member> members) {
        Map<String, String> m = new LinkedHashMap<>();
        for (Member x : members) m.put(x.name(), x.type());
        return m;
    }

    private Map<String, String> paramTypes(List<Param> params) {
        Map<String, String> m = new LinkedHashMap<>();
        for (Param x : params) m.put(x.name(), x.type());
        return m;
    }
}
