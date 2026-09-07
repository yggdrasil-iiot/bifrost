package dev.krillin.bifrost.heimdall;

/**
 * The plant could not be reached, so no verdict was possible.
 *
 * <p>This exists to keep one distinction the bridge previously lost: <b>"policy refused this
 * command" and "I cannot see the machine" are different events</b>, and collapsing them told the
 * operator that the model was wrong when the truth was that a server had restarted. It also drives
 * reconnection — a verdict is final, an unreachable plant is worth retrying.
 *
 * <p>It is still a refusal. The edge cannot confirm a write it was unable to make, so the command
 * does not succeed; only the reason, the counter and the retry differ.
 *
 * <p>It deliberately extends {@link Exception} rather than Milo's {@code UaException}: the
 * {@link Applier} seam exists so the bridge core is testable with no OPC-UA present, and typing the
 * seam to Milo would give that up for one line of brevity.
 */
public final class PlantUnreachableException extends Exception {

    private static final long serialVersionUID = 1L;

    public PlantUnreachableException(String message, Throwable cause) {
        super(message, cause);
    }

    public PlantUnreachableException(String message) {
        super(message);
    }
}
