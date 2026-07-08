package dev.krillin.bifrost.core.acl;
/** Authorization rule (implicit allow candidate). When {@code constraint} is null the rule is trigger-only: only {@code value=true} is permitted. */
public record Rule(String id, String principal, Target target, String command, Constraint constraint) {}
