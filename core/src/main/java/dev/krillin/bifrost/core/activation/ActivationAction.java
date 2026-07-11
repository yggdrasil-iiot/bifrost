package dev.krillin.bifrost.core.activation;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/** The two authorizable activation roles, serialized lowercase in the policy JSON. */
public enum ActivationAction {
    ACTIVATE, APPROVE;

    @JsonValue public String json() { return name().toLowerCase(); }

    @JsonCreator public static ActivationAction from(String s) {
        if (s == null) throw new IllegalArgumentException("action must not be null");
        return ActivationAction.valueOf(s.trim().toUpperCase());
    }
}
