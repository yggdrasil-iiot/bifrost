package dev.krillin.bifrost.sim;

import java.util.function.DoubleConsumer;

import org.eclipse.milo.opcua.sdk.server.methods.AbstractMethodInvocationHandler;
import org.eclipse.milo.opcua.sdk.server.methods.InvalidArgumentException;
import org.eclipse.milo.opcua.sdk.server.nodes.UaMethodNode;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.structured.Argument;

/**
 * {@code Line1/Mixer1.SetTemperature(targetTemperature: Double) -> appliedTemperature: Double}: the
 * OPC UA Method the governed write path (Vor M2) invokes through Heimdall. It sets the temperature
 * that {@code Line1/Mixer1.Temp} reports, so a reader observes the effect on the same member the
 * command's evidence was read from.
 *
 * <p><b>Argument checks are split between Milo and this handler, by design.</b> Milo's
 * {@link AbstractMethodInvocationHandler} already refuses a missing argument
 * ({@code Bad_ArgumentsMissing}) and a wrong type ({@code Bad_InvalidArgument} with
 * {@code Bad_TypeMismatch} for the argument) before this class sees the call. What it cannot know is
 * the range, so {@link #validateInputArgumentValues} refuses a non-finite or out-of-range value: the
 * call then fails with {@code Bad_InvalidArgument} and the argument's own result is
 * {@code Bad_OutOfRange}. A caller judging success must look at both.
 *
 * <p>The bounds are fixture limits for the gates, not a plant safety envelope — deliberately narrower
 * than the {@code MixerType.Temp} EURange (0..450), so an out-of-range command is easy to produce.
 */
final class SetTemperatureMethod extends AbstractMethodInvocationHandler {

    static final String IDENTIFIER = "Line1/Mixer1.SetTemperature";
    static final double MIN = 0.0;
    static final double MAX = 100.0;

    private static final long BAD_OUT_OF_RANGE = 0x803C0000L;

    static final Argument INPUT = new Argument("targetTemperature", NodeIds.Double, -1, null,
            LocalizedText.english("Target temperature in Cel, " + MIN + " to " + MAX + " inclusive"));
    static final Argument OUTPUT = new Argument("appliedTemperature", NodeIds.Double, -1, null,
            LocalizedText.english("The temperature applied, in Cel"));

    private final DoubleConsumer apply;

    /** @param apply sets the instance member; called only with a value that passed every check */
    SetTemperatureMethod(UaMethodNode node, DoubleConsumer apply) {
        super(node);
        this.apply = apply;
    }

    @Override
    public Argument[] getInputArguments() {
        return new Argument[] {INPUT};
    }

    @Override
    public Argument[] getOutputArguments() {
        return new Argument[] {OUTPUT};
    }

    /**
     * Written as "admit only if provably within", as {@code CommandAuthorizer} is, so NaN — which
     * compares false against every bound — is refused rather than slipping past both checks.
     */
    @Override
    protected void validateInputArgumentValues(Variant[] inputValues) throws InvalidArgumentException {
        double v = (Double) inputValues[0].getValue();
        if (!(Double.isFinite(v) && v >= MIN && v <= MAX)) {
            throw new InvalidArgumentException(new StatusCode[] {new StatusCode(BAD_OUT_OF_RANGE)});
        }
    }

    @Override
    protected Variant[] invoke(InvocationContext context, Variant[] inputValues) {
        double v = (Double) inputValues[0].getValue();
        apply.accept(v);
        return new Variant[] {new Variant(v)};
    }
}
