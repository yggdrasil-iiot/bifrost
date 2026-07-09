package dev.krillin.bifrost.core.activation;
import java.util.List;
import dev.krillin.bifrost.core.schema.Violation;
/** ok ⇒ event is the appended ActivationEvent, violations empty. refused ⇒ event null, ledger untouched. */
public record ActivationVerdict(boolean ok, ActivationEvent event, List<Violation> violations) {}
