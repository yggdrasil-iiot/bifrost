package dev.krillin.bifrost.core.acl;
/** Broker ACL entry (projection artifact; not live-enforced). */
public record AclEntry(String principal, String topicFilter, String permission) {}
