package dev.krillin.bifrost.core.command;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * One recorded fact about a runtime command.
 *
 * <p>A command produces up to two of these. The <b>intent</b> is written before the applier touches
 * the plant, so that "no command reaches the plant without a record" is a claim the edge can keep;
 * the <b>outcome</b> is written after, because what actually happened is only knowable then. A
 * refusal that never reaches the applier produces one entry and no outcome.
 *
 * <p>Deliberately not an {@code ActivationEvent}. An activation records which model version became
 * live; this records who asked for what and what happened. Forcing one record to carry both is how
 * a ledger stops being readable.
 *
 * <p><b>{@code subject} is null unless {@code REQUIRE_SIGNED_COMMAND} is on</b>, and that bar is off
 * by default. In a default deployment this is a record of what was decided, not of who asked.
 * {@code cmdId} and {@code value} are nullable for the same class of reason: both come off the
 * payload, and neither is required when the bar is off.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CommandEvent(String group, String edge, String cmdId, String subject,
                           String command, String value, String type,
                           String phase, String outcome, String reason, String at) {

    /** {@code phase} values. */
    public static final String INTENT = "intent";
    public static final String OUTCOME = "outcome";
}
