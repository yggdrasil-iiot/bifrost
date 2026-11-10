package yggdrasil.bifrost.core.conformance;
import java.util.List;
import yggdrasil.bifrost.core.schema.Violation;
public record ConformanceVerdict(boolean ok, List<Violation> violations) {}
