package dev.krillin.bifrost.core.activation;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The authorizable activation roles, serialized lowercase in the policy JSON.
 *
 * <p>{@code BREAK_GLASS_APPROVE} is the emergency approver role. A duty principal is granted it and
 * NOT {@code APPROVE}, which is what makes the emergency marking derived rather than claimed: the
 * one person holding a duty key cannot produce an unmarked activation, because no grant would
 * authorize one. A request flag could have been omitted; a missing grant cannot.
 */
public enum ActivationAction {
    ACTIVATE, APPROVE, BREAK_GLASS_APPROVE;

    @JsonValue public String json() { return name().toLowerCase(); }

    @JsonCreator public static ActivationAction from(String s) {
        if (s == null) throw new IllegalArgumentException("action must not be null");
        return ActivationAction.valueOf(s.trim().toUpperCase());
    }
}
