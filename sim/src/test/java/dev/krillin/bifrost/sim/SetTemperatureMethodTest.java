package dev.krillin.bifrost.sim;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Period;
import java.util.List;

import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.client.identity.X509IdentityProvider;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.enumerated.TimestampsToReturn;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodRequest;
import org.eclipse.milo.opcua.stack.core.types.structured.CallMethodResult;
import org.eclipse.milo.opcua.stack.core.util.SelfSignedCertificateBuilder;
import org.eclipse.milo.opcua.stack.core.util.SelfSignedCertificateGenerator;
import org.junit.jupiter.api.Test;

/**
 * {@code Line1/Mixer1.SetTemperature} over a real OPC UA Call: it sets {@code Line1/Mixer1.Temp},
 * refuses a bad argument without touching the member, and — when the sim requires an identity — is
 * executable only by the governed certificate, exactly as the setpoints are writable only by it.
 */
class SetTemperatureMethodTest {

    static final NodeId MIXER = NodeId.parse("ns=2;s=Line1/Mixer1");
    static final NodeId SET_TEMPERATURE = NodeId.parse("ns=2;s=" + SetTemperatureMethod.IDENTIFIER);
    static final NodeId TEMP = NodeId.parse("ns=2;s=Line1/Mixer1.Temp");
    static final String URL = "opc.tcp://localhost:" + EmbeddedMiloSim.BIND_PORT;

    static final long BAD_INVALID_ARGUMENT = 0x80AB0000L;
    static final long BAD_OUT_OF_RANGE = 0x803C0000L;
    static final long BAD_TYPE_MISMATCH = 0x80740000L;
    static final long BAD_ARGUMENTS_MISSING = 0x80760000L;
    static final long BAD_USER_ACCESS_DENIED = 0x801F0000L;

    @Test
    void anInRangeCallSetsTheMemberAndReturnsTheAppliedValue() throws Exception {
        try (EmbeddedMiloSim sim = new EmbeddedMiloSim().start()) {
            OpcUaClient client = anonymous();
            try {
                CallMethodResult r = call(client, new Variant(42.0));
                assertTrue(r.getStatusCode().isGood(), r.getStatusCode().toString());
                assertArrayEquals(new Variant[] {new Variant(42.0)}, r.getOutputArguments());
                assertEquals(42.0, temp(client));

                assertTrue(call(client, new Variant(SetTemperatureMethod.MIN)).getStatusCode().isGood());
                assertTrue(call(client, new Variant(SetTemperatureMethod.MAX)).getStatusCode().isGood(),
                        "both bounds are inclusive");
                assertEquals(SetTemperatureMethod.MAX, temp(client));
            } finally {
                client.disconnect();
            }
        }
    }

    @Test
    void eachMixersMethodSetsOnlyItsOwnTemp() throws Exception {
        NodeId mixer2 = NodeId.parse("ns=2;s=Line1/Mixer2"), temp2 = NodeId.parse("ns=2;s=Line1/Mixer2.Temp");
        try (EmbeddedMiloSim sim = new EmbeddedMiloSim().start()) {
            OpcUaClient client = anonymous();
            try {
                CallMethodResult r = client.call(List.of(new CallMethodRequest(mixer2,
                        NodeId.parse("ns=2;s=Line1/Mixer2.SetTemperature"), new Variant[] {new Variant(61.0)}))).getResults()[0];
                assertTrue(r.getStatusCode().isGood(), r.getStatusCode().toString());
                assertEquals(61.0, client.readValue(0, TimestampsToReturn.Both, temp2).getValue().getValue());
                assertEquals(200.0, temp(client), "Mixer1 is another piece of equipment");
                // Mixer1's Method is not a component of Mixer2: the server refuses the pairing.
                CallMethodResult crossed = client.call(List.of(new CallMethodRequest(mixer2, SET_TEMPERATURE,
                        new Variant[] {new Variant(62.0)}))).getResults()[0];
                assertTrue(crossed.getStatusCode().isBad(), crossed.getStatusCode().toString());
                assertEquals(200.0, temp(client));
            } finally {
                client.disconnect();
            }
        }
    }

    @Test
    void aBadArgumentIsRefusedAndTheMemberIsUntouched() throws Exception {
        try (EmbeddedMiloSim sim = new EmbeddedMiloSim().start()) {
            OpcUaClient client = anonymous();
            try {
                for (double v : new double[] {100.000001, -0.5, 150.0, Double.NaN, Double.POSITIVE_INFINITY}) {
                    CallMethodResult r = call(client, new Variant(v));
                    assertEquals(BAD_INVALID_ARGUMENT, r.getStatusCode().getValue(), "value " + v);
                    assertEquals(BAD_OUT_OF_RANGE, r.getInputArgumentResults()[0].getValue(), "value " + v);
                }
                CallMethodResult wrongType = call(client, new Variant("42"));
                assertEquals(BAD_INVALID_ARGUMENT, wrongType.getStatusCode().getValue());
                assertEquals(BAD_TYPE_MISMATCH, wrongType.getInputArgumentResults()[0].getValue());

                assertEquals(BAD_ARGUMENTS_MISSING, call(client).getStatusCode().getValue());
                assertEquals(200.0, temp(client), "no refused call reached the member");
            } finally {
                client.disconnect();
            }
        }
    }

    @Test
    void withIdentityRequiredOnlyTheGovernedCertificateMayCall() throws Exception {
        KeyPair kp = SelfSignedCertificateGenerator.generateRsaKeyPair(2048);
        X509Certificate cert = new SelfSignedCertificateBuilder(kp)
                .setCommonName("set-temperature-test-edge")
                .setApplicationUri("urn:bifrost:test:edge")
                .setValidityPeriod(Period.ofDays(1))
                .setSignatureAlgorithm(SelfSignedCertificateBuilder.SA_SHA256_RSA)
                .build();
        String thumbprint = GovernedWriteFilter.thumbprintOf(cert);
        try (EmbeddedMiloSim sim = new EmbeddedMiloSim(EmbeddedMiloSim.BIND_PORT, EmbeddedMiloSim.DEFAULT_BIND_HOST,
                true, thumbprint).start()) {
            OpcUaClient anon = OpcUaClient.create(URL,
                    eps -> eps.stream().filter(e -> e.getSecurityMode() == MessageSecurityMode.None).findFirst(),
                    t -> { }, c -> { });
            anon.connect();
            try {
                assertEquals(BAD_USER_ACCESS_DENIED, call(anon, new Variant(42.0)).getStatusCode().getValue());
                assertEquals(200.0, temp(anon));
            } finally {
                anon.disconnect();
            }

            OpcUaClient governed = OpcUaClient.create(URL,
                    eps -> eps.stream().filter(e -> SecurityPolicy.Basic256Sha256.getUri().equals(e.getSecurityPolicyUri())
                            && e.getSecurityMode() == MessageSecurityMode.SignAndEncrypt).findFirst(),
                    t -> { },
                    c -> c.setApplicationUri("urn:bifrost:test:edge")
                            .setCertificate(cert)
                            .setCertificateChain(new X509Certificate[] {cert})
                            .setKeyPair(kp)
                            .setIdentityProvider(new X509IdentityProvider(cert, kp.getPrivate())));
            governed.connect();
            try {
                assertTrue(call(governed, new Variant(55.0)).getStatusCode().isGood());
                assertEquals(55.0, temp(governed));
            } finally {
                governed.disconnect();
            }
        }
    }

    private static OpcUaClient anonymous() throws Exception {
        OpcUaClient client = OpcUaClient.create(URL);
        client.connect();
        return client;
    }

    private static CallMethodResult call(OpcUaClient client, Variant... inputs) throws Exception {
        return client.call(List.of(new CallMethodRequest(MIXER, SET_TEMPERATURE, inputs))).getResults()[0];
    }

    private static Object temp(OpcUaClient client) throws Exception {
        return client.readValue(0, TimestampsToReturn.Both, TEMP).getValue().getValue();
    }
}
