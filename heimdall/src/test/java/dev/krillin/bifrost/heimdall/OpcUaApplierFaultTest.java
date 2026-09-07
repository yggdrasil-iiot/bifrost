package dev.krillin.bifrost.heimdall;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.junit.jupiter.api.Test;

/**
 * Only the classification is unit-testable without a live server; the reconnect itself is proved
 * by {@code scripts/run-edge-resilience-gate.sh}, which kills the sim and requires recovery.
 */
class OpcUaApplierFaultTest {

    @Test
    void transportFaultsAreConnectionFaults() {
        assertTrue(OpcUaApplier.isConnectionFault(new StatusCode(StatusCodes.Bad_ConnectionClosed)));
        assertTrue(OpcUaApplier.isConnectionFault(new StatusCode(StatusCodes.Bad_SessionIdInvalid)));
        assertTrue(OpcUaApplier.isConnectionFault(new StatusCode(StatusCodes.Bad_ServerNotConnected)));
        assertTrue(OpcUaApplier.isConnectionFault(new StatusCode(StatusCodes.Bad_NotConnected)));
    }

    /** A value-level fault is NOT a connection fault — misclassifying it would hide a real refusal. */
    @Test
    void valueFaultsAreNotConnectionFaults() {
        assertFalse(OpcUaApplier.isConnectionFault(new StatusCode(StatusCodes.Bad_OutOfRange)));
        assertFalse(OpcUaApplier.isConnectionFault(new StatusCode(StatusCodes.Bad_TypeMismatch)));
        assertFalse(OpcUaApplier.isConnectionFault(StatusCode.GOOD));
        assertFalse(OpcUaApplier.isConnectionFault(null));
    }
}
