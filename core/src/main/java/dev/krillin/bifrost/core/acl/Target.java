package dev.krillin.bifrost.core.acl;
/** Command target. {@code device} is null for node-level commands. Wildcards ("*") are supported in {@code group} and {@code edge}. */
public record Target(String group, String edge, String device) {}
