package dev.krillin.bifrost.sim;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.eclipse.milo.opcua.sdk.core.Reference;
import org.eclipse.milo.opcua.sdk.server.EndpointConfig;
import org.eclipse.milo.opcua.sdk.server.ManagedNamespaceWithLifecycle;
import org.eclipse.milo.opcua.sdk.server.OpcUaServer;
import org.eclipse.milo.opcua.sdk.server.OpcUaServerConfig;
import org.eclipse.milo.opcua.sdk.server.identity.AnonymousIdentityValidator;
import org.eclipse.milo.opcua.sdk.server.items.DataItem;
import org.eclipse.milo.opcua.sdk.server.items.MonitoredItem;
import org.eclipse.milo.opcua.sdk.server.nodes.UaObjectTypeNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaVariableNode;
import org.eclipse.milo.opcua.stack.core.AttributeId;
import org.eclipse.milo.opcua.stack.core.Identifiers;
import org.eclipse.milo.opcua.stack.core.security.DefaultCertificateManager;
import org.eclipse.milo.opcua.stack.core.security.MemoryCertificateQuarantine;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.transport.TransportProfile;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.DateTime;
import org.eclipse.milo.opcua.stack.core.types.builtin.ExtensionObject;
import org.eclipse.milo.opcua.stack.core.types.builtin.LocalizedText;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned;
import org.eclipse.milo.opcua.stack.core.types.enumerated.MessageSecurityMode;
import org.eclipse.milo.opcua.stack.core.types.enumerated.UserTokenType;
import org.eclipse.milo.opcua.stack.core.types.structured.BuildInfo;
import org.eclipse.milo.opcua.stack.core.types.structured.Range;
import org.eclipse.milo.opcua.stack.core.types.structured.UserTokenPolicy;
import org.eclipse.milo.opcua.stack.transport.server.tcp.OpcTcpServerTransport;
import org.eclipse.milo.opcua.stack.transport.server.tcp.OpcTcpServerTransportConfig;

/**
 * In-JVM embedded Milo OPC-UA server for the bifrost-local runtime gate: a minimal stand-in for
 * the D3/PLC endpoint Heimdall's {@code OpcUaApplier} writes to. Minimal by design — it exposes
 * only what the gate needs (one writable Double setpoint node), with no trigger/done handshake,
 * polling thread, or multi-node model. Targets Milo <b>1.0.0</b>'s server API directly (package
 * layout, mandatory {@code OpcServerTransportFactory}, no bare {@code addUri} — a substantial
 * departure from the 0.6.12 server API), verified against the actual 1.0.0 jars.
 *
 * <p>Endpoint {@code opc.tcp://localhost:48400}, anonymous identity, {@code SecurityPolicy.None} —
 * matching exactly what {@code OpcUaApplier.connect()} (a bare {@code OpcUaClient.create(endpoint)}
 * + {@code connect()}) expects. Bind address/hostname are both {@code localhost} to avoid Milo's
 * endpoint-discovery hostname mismatch (the client re-resolves the advertised endpoint after
 * discovery; it must be reachable as exactly {@code localhost:48400}).
 */
final class EmbeddedMiloSim implements AutoCloseable {

    static final String NAMESPACE_URI = "urn:bifrost:opcua:sim";
    static final int BIND_PORT = 48400;

    private OpcUaServer server;
    private SimNamespace namespace;

    EmbeddedMiloSim start() throws Exception {
        EndpointConfig endpointConfig = EndpointConfig.newBuilder()
                .setTransportProfile(TransportProfile.TCP_UASC_UABINARY)
                .setBindAddress("localhost")
                .setBindPort(BIND_PORT)
                .setHostname("localhost")
                .setPath("")
                .setSecurityPolicy(SecurityPolicy.None)
                .setSecurityMode(MessageSecurityMode.None)
                .addTokenPolicies(new UserTokenPolicy("anonymous", UserTokenType.Anonymous, null, null, null))
                .build();

        // No security policy is actually exercised (SecurityPolicy.None / anonymous-only), but the
        // config builder still wants a CertificateManager — an in-memory, no-cert-groups instance is
        // sufficient since it is never consulted for this endpoint.
        DefaultCertificateManager certificateManager =
                new DefaultCertificateManager(new MemoryCertificateQuarantine(), List.of());

        OpcUaServerConfig serverConfig = OpcUaServerConfig.builder()
                .setApplicationUri("urn:bifrost:opcua:sim-server")
                .setApplicationName(LocalizedText.english("Bifrost OPC-UA Sim"))
                .setProductUri("urn:bifrost:opcua:sim-server")
                .setEndpoints(Set.of(endpointConfig))
                .setBuildInfo(new BuildInfo(
                        "urn:bifrost:opcua:sim-server", "krillin", "bifrost opc-ua sim",
                        "0.1.0", "", DateTime.now()))
                .setCertificateManager(certificateManager)
                .setIdentityValidator(AnonymousIdentityValidator.INSTANCE)
                .build();

        server = new OpcUaServer(serverConfig, transportProfile -> {
            assert transportProfile == TransportProfile.TCP_UASC_UABINARY;
            return new OpcTcpServerTransport(OpcTcpServerTransportConfig.newBuilder().build());
        });

        // Pre-register the namespace URI so the custom namespace gets index 2 deterministically
        // (index 0 = OPC-UA foundation, index 1 = server application URI).
        server.getNamespaceTable().add(NAMESPACE_URI);
        namespace = new SimNamespace(server);
        namespace.startup();
        server.startup().get(30, TimeUnit.SECONDS);

        return this;
    }

    @Override
    public void close() {
        if (server != null) {
            try {
                namespace.shutdown();
            } catch (Exception ignore) {
                // best-effort
            }
            try {
                server.shutdown().get(10, TimeUnit.SECONDS);
            } catch (Exception ignore) {
                // best-effort
            }
        }
    }

    /** Internal namespace: exposes ns=2;s=Recipe/Rpm (and Recipe/Temp) as writable Doubles. */
    static final class SimNamespace extends ManagedNamespaceWithLifecycle {

        SimNamespace(OpcUaServer server) {
            super(server, NAMESPACE_URI);
            getLifecycleManager().addStartupTask(this::createNodes);
        }

        private void createNodes() {
            UaVariableNode rpm = makeDoubleNode("Recipe/Rpm", "Rpm", 0.0);
            rpm.addAttributeObserver((node, attributeId, value) -> {
                if (attributeId == AttributeId.Value) {
                    Object v = value instanceof DataValue dv && dv.getValue() != null
                            ? dv.getValue().getValue()
                            : value;
                    System.out.println("[SIM] SET ns=2;s=Recipe/Rpm = " + v);
                }
            });

            makeDoubleNode("Recipe/Temp", "Temp", 0.0);

            createMixerType();
        }

        private UaVariableNode makeDoubleNode(String identifier, String browseName, double initial) {
            return new UaVariableNode.UaVariableNodeBuilder(getNodeContext())
                    .setNodeId(newNodeId(identifier))
                    .setBrowseName(newQualifiedName(browseName))
                    .setDisplayName(LocalizedText.english(browseName))
                    .setDataType(Identifiers.Double)
                    .setTypeDefinition(Identifiers.BaseDataVariableType)
                    .setAccessLevel(Unsigned.ubyte(3))
                    .setUserAccessLevel(Unsigned.ubyte(3))
                    .setValue(new DataValue(new Variant(initial)))
                    .buildAndAdd();
        }

        /**
         * MixerType ObjectType (ns=2;s=MixerType): a Mixer's members (Rpm, Temp, Running, Secret)
         * plus EURange engineering-range properties on the numeric members (Rpm, Temp). Exposed so a
         * future northbound "Mímir" app can browse the TYPE (not an instance) to derive a canonical
         * spec definition.
         */
        private void createMixerType() {
            UaObjectTypeNode mixerType = new UaObjectTypeNode.UaObjectTypeNodeBuilder(getNodeContext())
                    .setNodeId(newNodeId("MixerType"))
                    .setBrowseName(newQualifiedName("MixerType"))
                    .setDisplayName(LocalizedText.english("MixerType"))
                    .setIsAbstract(false)
                    .buildAndAdd();
            // MixerType is-subtype-of BaseObjectType (inverse HasSubtype); a browser walks this up.
            mixerType.addReference(new Reference(mixerType.getNodeId(), Identifiers.HasSubtype,
                    Identifiers.BaseObjectType.expanded(), false));

            UaVariableNode rpm = typeMember("MixerType.Rpm", "Rpm", Identifiers.Double, 0.0);
            UaVariableNode temp = typeMember("MixerType.Temp", "Temp", Identifiers.Double, 0.0);
            UaVariableNode run = typeMember("MixerType.Running", "Running", Identifiers.Boolean, false);
            UaVariableNode sec = typeMember("MixerType.Secret", "Secret", Identifiers.Double, 0.0);
            mixerType.addComponent(rpm);
            mixerType.addComponent(temp);
            mixerType.addComponent(run);
            mixerType.addComponent(sec);
            attachEuRange(rpm, "MixerType.Rpm.EURange", 0.0, 3000.0);
            attachEuRange(temp, "MixerType.Temp.EURange", 0.0, 450.0);
        }

        private UaVariableNode typeMember(String id, String name, NodeId dataType, Object initial) {
            return new UaVariableNode.UaVariableNodeBuilder(getNodeContext())
                    .setNodeId(newNodeId(id)).setBrowseName(newQualifiedName(name))
                    .setDisplayName(LocalizedText.english(name))
                    .setDataType(dataType).setTypeDefinition(Identifiers.BaseDataVariableType)
                    .setAccessLevel(Unsigned.ubyte(1)).setUserAccessLevel(Unsigned.ubyte(1))
                    .setValue(new DataValue(new Variant(initial))).buildAndAdd();
        }

        private void attachEuRange(UaVariableNode member, String id, double low, double high) {
            ExtensionObject eu = ExtensionObject.encode(
                    getNodeContext().getServer().getStaticEncodingContext(), new Range(low, high));
            UaVariableNode euRange = new UaVariableNode.UaVariableNodeBuilder(getNodeContext())
                    .setNodeId(newNodeId(id)).setBrowseName(newQualifiedName("EURange"))
                    .setDisplayName(LocalizedText.english("EURange"))
                    .setDataType(Identifiers.Range).setTypeDefinition(Identifiers.PropertyType)
                    .setValue(new DataValue(new Variant(eu))).buildAndAdd();
            // NB: UaNode.addProperty(...) is PACKAGE-PRIVATE (uncallable from this package) — wire
            // HasProperty explicitly.
            member.addReference(new Reference(member.getNodeId(), Identifiers.HasProperty,
                    euRange.getNodeId().expanded(), /* forward */ true));
        }

        @Override
        public void onDataItemsCreated(List<DataItem> dataItems) {
        }

        @Override
        public void onDataItemsModified(List<DataItem> dataItems) {
        }

        @Override
        public void onDataItemsDeleted(List<DataItem> dataItems) {
        }

        @Override
        public void onMonitoringModeChanged(List<MonitoredItem> monitoredItems) {
        }
    }
}
