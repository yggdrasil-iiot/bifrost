package dev.krillin.bifrost.core.acl;
/** Authorization input. {@code value} is the received metric value (Object); {@code type} is MetricDataType.toString(). */
public record CommandRequest(Target target, String command, Object value, String type) {}
