package dev.krillin.bifrost.core.acl;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/** Single source of truth for policy-as-code. {@code defaultEffect} maps to JSON key {@code "default"} and defines the effect on no-match; must always be {@code "deny"}. */
public record CommandPolicy(String version, List<Rule> rules,
                            @JsonProperty("default") String defaultEffect) {}
