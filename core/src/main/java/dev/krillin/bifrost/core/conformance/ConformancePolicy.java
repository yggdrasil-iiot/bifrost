package dev.krillin.bifrost.core.conformance;
import java.util.List;
/** Governed declarative conformance config (the IAM-like policy artifact). Dial holds the strictness mode
 *  ("envelope"|"recipe") and, for recipe-mode, the active recipe ref + tolerance. */
public record ConformancePolicy(String policyRef, String version, String equipmentRef, String equipmentVersion,
                                Dial dial, List<CrossConstraint> crossConstraints, List<NodeBinding> nodeBindings) {
    public record Dial(String mode, String activeRecipeRef, String activeRecipeVersion, Double recipeTolerance) {}
    public List<CrossConstraint> crossConstraints() { return crossConstraints == null ? List.of() : crossConstraints; }
    public List<NodeBinding> nodeBindings() { return nodeBindings == null ? List.of() : nodeBindings; }
}
