package dev.krillin.bifrost.core.schema;

import java.util.List;

/** Spec-conformance check result: conformant=true if and only if violations is empty. */
public record SpecVerdict(boolean conformant, List<Violation> violations) {}
