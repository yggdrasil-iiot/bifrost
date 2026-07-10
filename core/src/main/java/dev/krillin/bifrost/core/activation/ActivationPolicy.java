package dev.krillin.bifrost.core.activation;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/** Deny-by-default policy-as-code for the activation act (mirrors core.acl.CommandPolicy). {@code default}
 *  must be "deny"; an empty/absent rule list denies everything. */
public record ActivationPolicy(String version, List<ActivationRule> rules,
                               @JsonProperty("default") String defaultEffect) {

    /** The fail-closed policy used when no policy file is present: no rules, deny everything. */
    public static ActivationPolicy denyAll() {
        return new ActivationPolicy("(none)", List.of(), "deny");
    }
}
