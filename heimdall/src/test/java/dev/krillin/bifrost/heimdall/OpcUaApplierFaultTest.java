package dev.krillin.bifrost.heimdall;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
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

    // ----- R3: endpoint selection -----

    /**
     * The failure that matters here is a SILENT DOWNGRADE. If the picker accepted None, the edge
     * would connect happily while presenting no identity at all, and row 12's whole point would be
     * lost behind a green log line.
     */
    @Test
    void onlySignAndEncryptOnBasic256Sha256Counts() {
        assertTrue(OpcUaApplier.isSecure(
                SecurityPolicy.Basic256Sha256.getUri(), MessageSecurityMode.SignAndEncrypt));
        assertFalse(OpcUaApplier.isSecure(
                SecurityPolicy.None.getUri(), MessageSecurityMode.None),
                "an anonymous None endpoint must never be selected when an identity is configured");
        assertFalse(OpcUaApplier.isSecure(
                SecurityPolicy.Basic256Sha256.getUri(), MessageSecurityMode.Sign),
                "Sign without Encrypt is not what this round claims to establish");
        assertFalse(OpcUaApplier.isSecure(null, MessageSecurityMode.SignAndEncrypt));
        assertFalse(OpcUaApplier.isSecure(SecurityPolicy.Basic256Sha256.getUri(), null));
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
