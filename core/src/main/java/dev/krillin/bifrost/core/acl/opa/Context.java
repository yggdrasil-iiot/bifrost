package dev.krillin.bifrost.core.acl.opa;
/** Operational context supplied to the policy (lab-local input; no cross-repo feed). */
public record Context(String state, int hour) {}
