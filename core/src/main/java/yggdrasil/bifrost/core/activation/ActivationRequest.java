package yggdrasil.bifrost.core.activation;
public record ActivationRequest(String target, String kind, String ref, String version,
                                String by, String approvedBy, boolean rollback) {}
