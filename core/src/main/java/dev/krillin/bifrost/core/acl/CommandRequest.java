package dev.krillin.bifrost.core.acl;

/**
 * Authorization input. {@code value} is the received metric value (Object); {@code type} is
 * MetricDataType.toString().
 *
 * <p>{@code subject} is the principal the caller has <b>verified</b>, or null when none was
 * asserted. Null is deliberately not "anonymous": {@link CommandAuthorizer} skips the principal
 * check for it, and what makes that safe is the edge's {@code REQUIRE_SIGNED_COMMAND} bar, which
 * refuses an unsigned command outright before this record is ever built.
 */
public record CommandRequest(Target target, String command, Object value, String type, String subject) {

    /**
     * The pre-R1 shape: no subject asserted. A non-canonical delegating constructor, so every
     * existing construction site keeps compiling unchanged.
     */
    public CommandRequest(Target target, String command, Object value, String type) {
        this(target, command, value, type, null);
    }
}
