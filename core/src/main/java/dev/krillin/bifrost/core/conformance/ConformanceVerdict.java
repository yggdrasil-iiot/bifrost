package dev.krillin.bifrost.core.conformance;
import java.util.List;
import dev.krillin.bifrost.core.schema.Violation;
public record ConformanceVerdict(boolean ok, List<Violation> violations) {}
