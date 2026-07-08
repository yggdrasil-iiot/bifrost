package dev.krillin.bifrost.core.conformance;
import java.util.*;
import dev.krillin.bifrost.core.schema.*;

/** Pure composed conformance evaluator (the IAM-like policy evaluation engine). Rules: structural,
 *  type, envelope (from model), cross-member (from policy), recipe (recipe-mode). Violations accumulate. */
public final class ConformanceEvaluator {

    public ConformanceVerdict evaluate(UdtDefinition def, ConformancePolicy policy,
            MasterSpec activeRecipe, List<Setpoint> state) {
        List<Violation> v = new ArrayList<>();
        Map<String, Member> members = new LinkedHashMap<>();
        for (Member m : def.members()) members.put(m.name(), m);
        Map<String, Double> values = new LinkedHashMap<>();
        for (Setpoint s : state) values.put(s.member(), s.value());

        // structural + type + envelope, per candidate setpoint
        for (Setpoint s : state) {
            Member m = members.get(s.member());
            if (m == null) { v.add(new Violation("spec.member.unknown",
                    "setpoint targets member '" + s.member() + "' absent from '" + def.templateRef() + "'")); continue; }
            if (!m.type().equals(s.type())) v.add(new Violation("spec.type.mismatch",
                    "member '" + s.member() + "' type " + m.type() + " but setpoint " + s.type()));
            if (m.range() != null) {
                if (s.value() < m.range().low()) v.add(new Violation("spec.range.below-min",
                        "member '" + s.member() + "' value " + s.value() + " is below min " + m.range().low()));
                if (s.value() > m.range().high()) v.add(new Violation("spec.range.above-max",
                        "member '" + s.member() + "' value " + s.value() + " is above max " + m.range().high()));
            }
        }
        // cross-member (policy)
        if (policy != null) {
            for (CrossConstraint c : policy.crossConstraints()) {
                Double a = values.get(c.ifMember());
                Double b = values.get(c.thenMember());
                if (a == null || b == null) continue;              // both members must be present in the state
                if (cmp(a, c.ifOp(), c.ifValue()) && !cmp(b, c.thenOp(), c.thenValue())) {
                    v.add(new Violation("conformance.cross." + c.id(),
                        "cross-member " + c.id() + ": when " + c.ifMember() + " " + c.ifOp() + " " + c.ifValue()
                        + ", require " + c.thenMember() + " " + c.thenOp() + " " + c.thenValue()
                        + " (was " + b + ") — e.g. weld-lobe above-max"));
                }
            }
        }
        // recipe-mode
        if (policy != null && policy.dial() != null && "recipe".equals(policy.dial().mode()) && activeRecipe != null) {
            double tol = policy.dial().recipeTolerance() == null ? 0.0 : policy.dial().recipeTolerance();
            Map<String, Double> recipe = new LinkedHashMap<>();
            for (Setpoint s : activeRecipe.setpoints()) recipe.put(s.member(), s.value());
            for (Setpoint s : state) {
                Double target = recipe.get(s.member());
                if (target == null) continue;
                if (Math.abs(s.value() - target) > Math.abs(target) * tol) v.add(new Violation("conformance.recipe.deviation",
                        "member '" + s.member() + "' value " + s.value() + " deviates from approved recipe setpoint " + target));
            }
        }
        return new ConformanceVerdict(v.isEmpty(), List.copyOf(v));
    }

    private static boolean cmp(double x, String op, double y) {
        return switch (op) {
            case "lt" -> x < y; case "le" -> x <= y; case "gt" -> x > y; case "ge" -> x >= y; case "eq" -> x == y;
            default -> throw new IllegalArgumentException("bad op: " + op);
        };
    }
}
