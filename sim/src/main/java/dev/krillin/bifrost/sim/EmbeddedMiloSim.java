package dev.krillin.bifrost.sim;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Period;
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
import org.eclipse.milo.opcua.sdk.server.identity.CompositeValidator;
import org.eclipse.milo.opcua.sdk.server.identity.X509IdentityValidator;
import org.eclipse.milo.opcua.sdk.server.items.DataItem;
import org.eclipse.milo.opcua.sdk.server.items.MonitoredItem;
import org.eclipse.milo.opcua.sdk.server.nodes.UaObjectNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaObjectTypeNode;
import org.eclipse.milo.opcua.sdk.server.nodes.UaVariableNode;
import org.eclipse.milo.opcua.stack.core.AttributeId;
import org.eclipse.milo.opcua.stack.core.Identifiers;
import org.eclipse.milo.opcua.stack.core.security.CertificateGroup;
import org.eclipse.milo.opcua.stack.core.security.CertificateValidator;
import org.eclipse.milo.opcua.stack.core.security.DefaultApplicationGroup;
import org.eclipse.milo.opcua.stack.core.security.DefaultCertificateManager;
import org.eclipse.milo.opcua.stack.core.security.MemoryCertificateStore;
import org.eclipse.milo.opcua.stack.core.security.MemoryCertificateQuarantine;
import org.eclipse.milo.opcua.stack.core.security.MemoryTrustListManager;
import org.eclipse.milo.opcua.stack.core.security.RsaSha256CertificateFactory;
import org.eclipse.milo.opcua.stack.core.security.SecurityPolicy;
import org.eclipse.milo.opcua.stack.core.transport.TransportProfile;
import org.eclipse.milo.opcua.stack.core.util.SelfSignedCertificateBuilder;
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
 * writable Double setpoint nodes plus a single rising-edge activate handshake (a writable Boolean
 * trigger + a sim-owned done flag) matching {@code OpcUaApplier.call()}; no polling thread or
 * broader equipment model. Targets Milo <b>1.0.0</b>'s server API directly (package
 * layout, mandatory {@code OpcServerTransportFactory}, no bare {@code addUri} — a substantial
 * departure from the 0.6.12 server API), verified against the actual 1.0.0 jars.
 *
 * <p>Endpoint is configurable (default {@code opc.tcp://localhost:48400}), anonymous identity, {@code SecurityPolicy.None} —
 * matching exactly what {@code OpcUaApplier.connect()} (a bare {@code OpcUaClient.create(endpoint)}
 * + {@code connect()}) expects. Bind address/hostname are both {@code localhost} to avoid Milo's
 * endpoint-discovery hostname mismatch (the client re-resolves the advertised endpoint after
 * discovery; it must be reachable as exactly {@code localhost:48400}).
 */
final class EmbeddedMiloSim implements AutoCloseable {

    static final String NAMESPACE_URI = "urn:bifrost:opcua:sim";
    static final int BIND_PORT = 48400;              // RETAINED default (existing tests reference this)
    static final String DEFAULT_BIND_HOST = "localhost";

    private final int bindPort;
    private final String bindHost;

    /**
     * R3: add a Basic256Sha256/SignAndEncrypt endpoint requiring the governed X.509 identity, and
     * make the controlled nodes read-only for every other session. Default OFF, so every gate that
     * predates this still exercises the anonymous endpoint it was written against.
     */
    private final boolean requireIdentity;
    private final String governedThumbprint;

    private OpcUaServer server;
    private SimNamespace namespace;

    EmbeddedMiloSim() { this(BIND_PORT, DEFAULT_BIND_HOST); }

    EmbeddedMiloSim(int bindPort, String bindHost) { this(bindPort, bindHost, false, null); }

    EmbeddedMiloSim(int bindPort, String bindHost, boolean requireIdentity, String governedThumbprint) {
        this.bindPort = bindPort;
        this.bindHost = bindHost;
        this.requireIdentity = requireIdentity;
        this.governedThumbprint = governedThumbprint;
    }

    int bindPort() { return bindPort; }
    String bindHost() { return bindHost; }

    /**
     * The certificate group a Basic256Sha256 endpoint requires. The sim previously had none at all
     * — {@code DefaultCertificateManager} was built with an empty group list because
     * SecurityPolicy.None never consults it.
     *
     * <p><b>The validator here is deliberately insecure, and the reason matters.</b> It validates
     * INCOMING CLIENT APPLICATION certificates, before any user token is examined. A strict
     * validator over an empty trust list would reject the governed edge's secure channel before its
     * X.509 user token was ever looked at — the write-exclusivity gate would fail for a reason that
     * has nothing to do with identity, and its untrusted-certificate leg would pass for a reason
     * that has nothing to do with the thumbprint. Accepting the application certificate and letting
     * the thumbprint predicate be the decision keeps the gate measuring the thing it names.
     *
     * <p>It is also exactly axis 10's gap: real trust needs a populated trust list, which is the
     * same missing PKI that has no rotation and no revocation.
     */
    private CertificateGroup securityGroup() throws Exception {
        return DefaultApplicationGroup.createAndInitialize(
                new MemoryTrustListManager(),
                new MemoryCertificateStore(),
                new RsaSha256CertificateFactory() {
                    @Override
                    protected X509Certificate[] createRsaSha256CertificateChain(KeyPair keyPair) throws Exception {
                        return new X509Certificate[] {
                            new SelfSignedCertificateBuilder(keyPair)
                                    .setCommonName("Bifrost OPC-UA Sim")
                                    .setOrganization("yggdrasil-iiot")
                                    .setApplicationUri("urn:bifrost:opcua:sim-server")
                                    .setValidityPeriod(Period.ofYears(2))
                                    .setSignatureAlgorithm(SelfSignedCertificateBuilder.SA_SHA256_RSA)
                                    .build()
                        };
                    }
                },
                new CertificateValidator.InsecureCertificateValidator());
    }

    /** The server's own certificate out of the group, for the secured endpoint to present. */
    private static X509Certificate serverCertificate(CertificateGroup group) throws Exception {
        NodeId typeId = group.getSupportedCertificateTypeIds().get(0);
        X509Certificate[] chain = group.getCertificateChain(typeId)
                .orElseThrow(() -> new IllegalStateException(
                        "certificate group produced no chain for " + typeId));
        return chain[0];
    }

    EmbeddedMiloSim start() throws Exception {
        EndpointConfig endpointConfig = EndpointConfig.newBuilder()
                .setTransportProfile(TransportProfile.TCP_UASC_UABINARY)
                .setBindAddress(bindHost)
                .setBindPort(bindPort)
                .setHostname(bindHost)
                .setPath("")
                .setSecurityPolicy(SecurityPolicy.None)
                .setSecurityMode(MessageSecurityMode.None)
                .addTokenPolicies(new UserTokenPolicy("anonymous", UserTokenType.Anonymous, null, null, null))
                .build();

        // The anonymous endpoint above stays even when identity is required: a plant needs
        // read-only clients (historians, HMIs) and locking them out is not what write-path
        // exclusivity means. Only the WRITE bit moves, via GovernedWriteFilter.
        Set<EndpointConfig> endpoints = new LinkedHashSet<>();
        endpoints.add(endpointConfig);

        // Built before the secured endpoint because the endpoint itself needs the certificate:
        // EndpointConfig.Builder.build() throws "security requires certificate" without it. Holding
        // it in the CertificateManager alone is not enough.
        CertificateGroup group = requireIdentity ? securityGroup() : null;

        // Without identity: an in-memory, NO-cert-groups manager is enough, because SecurityPolicy
        // .None never consults it. With identity: a Basic256Sha256 endpoint means the server must
        // hold its own key material, which needs a real certificate group.
        DefaultCertificateManager certificateManager = requireIdentity
                ? new DefaultCertificateManager(new MemoryCertificateQuarantine(), List.of(group))
                : new DefaultCertificateManager(new MemoryCertificateQuarantine(), List.of());

        if (requireIdentity) {
            endpoints.add(EndpointConfig.newBuilder()
                    .setTransportProfile(TransportProfile.TCP_UASC_UABINARY)
                    .setBindAddress(bindHost)
                    .setBindPort(bindPort)
                    .setHostname(bindHost)
                    .setPath("")
                    .setSecurityPolicy(SecurityPolicy.Basic256Sha256)
                    .setSecurityMode(MessageSecurityMode.SignAndEncrypt)
                    .setCertificate(serverCertificate(group))
                    // A null securityPolicyUri makes AbstractX509IdentityValidator fall back to the
                    // channel's policy, which is what we want on a Basic256Sha256 endpoint.
                    .addTokenPolicies(new UserTokenPolicy("x509", UserTokenType.Certificate, null, null, null))
                    .build());
        }

        OpcUaServerConfig serverConfig = OpcUaServerConfig.builder()
                .setApplicationUri("urn:bifrost:opcua:sim-server")
                .setApplicationName(LocalizedText.english("Bifrost OPC-UA Sim"))
                .setProductUri("urn:bifrost:opcua:sim-server")
                .setEndpoints(endpoints)
                .setBuildInfo(new BuildInfo(
                        "urn:bifrost:opcua:sim-server", "krillin", "bifrost opc-ua sim",
                        "0.1.0", "", DateTime.now()))
                .setCertificateManager(certificateManager)
                // The thumbprint predicate is the whole authorization decision for the secured
                // endpoint. It fails closed on an unconfigured thumbprint, matching
                // GovernedWriteFilter: "require an identity" with no identity named must mean
                // nobody, never everybody.
                // COMPOSITE, not a replacement. Swapping the anonymous validator out entirely
                // would refuse anonymous sessions at ACTIVATION - a total lockout rather than
                // read-only, which is a stronger claim than §12 makes and a worse model of a plant:
                // historians and HMIs must still be able to read. Anonymous stays valid; presenting
                // the governed certificate is what unlocks the WRITE bit, via GovernedWriteFilter.
                .setIdentityValidator(requireIdentity
                        ? new CompositeValidator(
                                AnonymousIdentityValidator.INSTANCE,
                                new X509IdentityValidator(cert -> governedThumbprint != null
                                        && !governedThumbprint.isBlank()
                                        && governedThumbprint.trim().equalsIgnoreCase(
                                                GovernedWriteFilter.thumbprintOf(cert))))
                        : AnonymousIdentityValidator.INSTANCE)
                .build();

        server = new OpcUaServer(serverConfig, transportProfile -> {
            assert transportProfile == TransportProfile.TCP_UASC_UABINARY;
            return new OpcTcpServerTransport(OpcTcpServerTransportConfig.newBuilder().build());
        });

        // Pre-register the namespace URI so the custom namespace gets index 2 deterministically
        // (index 0 = OPC-UA foundation, index 1 = server application URI).
        server.getNamespaceTable().add(NAMESPACE_URI);
        namespace = new SimNamespace(server, requireIdentity ? new GovernedWriteFilter(governedThumbprint) : null);
        namespace.startup();
        server.startup().get(30, TimeUnit.SECONDS);

        if (requireIdentity) {
            // Printed only AFTER startup succeeds. OpcUaServer logs a failed endpoint bind as a
            // WARN and carries on, so without this line the sim would announce itself as listening
            // while offering no secured endpoint at all, and the gate would test nothing.
            System.out.println("[SIM] secured endpoint Basic256Sha256/SignAndEncrypt, governed thumbprint "
                    + governedThumbprint);
        }
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

    /**
     * Internal namespace: exposes ns=2;s=Recipe/Rpm (and Recipe/Temp) as writable Doubles, plus the
     * ns=2;s=Recipe/ApplyRecipe trigger + ns=2;s=Recipe/ApplyDone rising-edge activate handshake.
     */
    static final class SimNamespace extends ManagedNamespaceWithLifecycle {

        /** Null when identity is not required, in which case the nodes keep UserAccessLevel 3. */
        private final GovernedWriteFilter writeFilter;

        SimNamespace(OpcUaServer server, GovernedWriteFilter writeFilter) {
            super(server, NAMESPACE_URI);
            this.writeFilter = writeFilter;
            getLifecycleManager().addStartupTask(this::createNodes);
        }

        /**
         * Put the controlled nodes behind the governed-write filter.
         *
         * <p>The set is every node a client can WRITE and that matters to the governed model:
         * Rpm and Temp are the setpoints, ApplyRecipe is the activate trigger
         * {@code OpcUaApplier.call()} fires, ApplyDone is the equipment's confirmation, and
         * WeldCurrent is the second line's setpoint. <b>ApplyRecipe is the one that is easy to
         * forget and the worst to miss</b>: an anonymous client able to fire a recipe apply, while
         * the project claims write-path exclusivity, is a hole in the claim itself. ApplyDone is
         * included for the mirror-image reason — writing it fakes a confirmation.
         *
         * <p>Running needs nothing: {@code typeMember} already builds it at access level 1.
         */
        private void govern(UaVariableNode... nodes) {
            if (writeFilter == null) {
                return;
            }
            for (UaVariableNode n : nodes) {
                n.getFilterChain().addFirst(writeFilter);
            }
        }

        private void createNodes() {
            UaVariableNode rpm = makeDoubleNode("Recipe/Rpm", "Rpm", 0.0);
            rpm.addAttributeObserver((node, attributeId, value) -> {
                if (attributeId == AttributeId.Value) {
                    Object v = value instanceof DataValue dv && dv.getValue() != null
                            ? dv.getValue().getValue()
                            : value;
                    System.out.println("[SIM] SET ns=2;s=Recipe/Rpm = " + v);
                    transferToInstance("Line1/Mixer1.Rpm", v);
                }
            });

            UaVariableNode temp = makeDoubleNode("Recipe/Temp", "Temp", 0.0);
            temp.addAttributeObserver((node, attributeId, value) -> {
                if (attributeId == AttributeId.Value) {
                    Object v = value instanceof DataValue dv && dv.getValue() != null
                            ? dv.getValue().getValue()
                            : value;
                    System.out.println("[SIM] SET ns=2;s=Recipe/Temp = " + v);
                    transferToInstance("Line1/Mixer1.Temp", v);
                }
            });

            // Rising-edge activate handshake: ApplyRecipe is the writable Boolean TRIGGER, ApplyDone
            // is the DONE flag the sim owns. Heimdall's OpcUaApplier.call() writes ApplyRecipe=true,
            // polls ApplyDone until true (confirm), then writes ApplyRecipe=false to release/rearm.
            UaVariableNode applyDone = makeBooleanNode("Recipe/ApplyDone", "ApplyDone", false);
            UaVariableNode applyRecipe = makeBooleanNode("Recipe/ApplyRecipe", "ApplyRecipe", false);
            applyRecipe
                    .addAttributeObserver((node, attributeId, value) -> {
                        if (attributeId == AttributeId.Value) {
                            Object v = value instanceof DataValue dv && dv.getValue() != null
                                    ? dv.getValue().getValue()
                                    : value;
                            System.out.println("[SIM] SET ns=2;s=Recipe/ApplyRecipe = " + v);
                            // Rising edge (trigger -> true) sets done; release (trigger -> false) rearms done.
                            applyDone.setValue(new DataValue(new Variant(Boolean.TRUE.equals(v))));
                        }
                    });

            createMixerType();
            createMixerInstance();

            UaVariableNode weldCurrent = makeDoubleNode("Weld/WeldCurrent", "WeldCurrent", 0.0);
            // Every client-writable node that matters to the governed model. See govern()'s javadoc
            // for why ApplyRecipe and ApplyDone are in this list and Running is not.
            govern(rpm, temp, applyRecipe, applyDone, weldCurrent);
            weldCurrent.addAttributeObserver((node, attributeId, value) -> {
                if (attributeId == AttributeId.Value) {
                    Object v = value instanceof DataValue dv && dv.getValue() != null
                            ? dv.getValue().getValue()
                            : value;
                    System.out.println("[SIM] SET ns=2;s=Weld/WeldCurrent = " + v);
                    transferToInstance("BodyShop/Weld1.WeldCurrent", v);
                }
            });

            createWeldType();
            createWeldInstance();
        }

        /**
         * Internal setpoint -> PV transfer (models "command applied, PV settles to setpoint",
         * instant/no-dynamics). Resolves the instance node lazily at write-time (it is created
         * after the Recipe observers are wired) and sets it server-side, bypassing the instance's
         * client-read-only access level (same mechanism as the ApplyDone handshake).
         */
        private void transferToInstance(String instanceIdentifier, Object value) {
            getNodeManager().getNode(newNodeId(instanceIdentifier)).ifPresent(n -> {
                if (n instanceof UaVariableNode v) {
                    v.setValue(new DataValue(new Variant(value)));
                    System.out.println("[SIM] transfer " + instanceIdentifier + " = " + value);
                }
            });
        }

        private UaVariableNode makeBooleanNode(String identifier, String browseName, boolean initial) {
            return new UaVariableNode.UaVariableNodeBuilder(getNodeContext())
                    .setNodeId(newNodeId(identifier))
                    .setBrowseName(newQualifiedName(browseName))
                    .setDisplayName(LocalizedText.english(browseName))
                    .setDataType(Identifiers.Boolean)
                    .setTypeDefinition(Identifiers.BaseDataVariableType)
                    .setAccessLevel(Unsigned.ubyte(3))
                    .setUserAccessLevel(Unsigned.ubyte(3))
                    .setValue(new DataValue(new Variant(initial)))
                    .buildAndAdd();
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

        /**
         * Line1/Mixer1: a concrete Mixer instance typed by MixerType, browsable under the Objects
         * folder, with its four members seeded to static values (no polling/update thread — the
         * static seed is intentional and in scope for this gate).
         */
        private void createMixerInstance() {
            UaObjectNode mixer1 = new UaObjectNode.UaObjectNodeBuilder(getNodeContext())
                    .setNodeId(newNodeId("Line1/Mixer1"))
                    .setBrowseName(newQualifiedName("Mixer1"))
                    .setDisplayName(LocalizedText.english("Mixer1"))
                    .setTypeDefinition(newNodeId("MixerType"))
                    .buildAndAdd();
            // Browsable under the Objects folder (inverse Organizes).
            mixer1.addReference(new Reference(mixer1.getNodeId(), Identifiers.Organizes,
                    Identifiers.ObjectsFolder.expanded(), false));
            UaVariableNode iRpm = typeMember("Line1/Mixer1.Rpm", "Rpm", Identifiers.Double, 1535.0);
            UaVariableNode iTemp = typeMember("Line1/Mixer1.Temp", "Temp", Identifiers.Double, 200.0);
            UaVariableNode iRun = typeMember("Line1/Mixer1.Running", "Running", Identifiers.Boolean, true);
            UaVariableNode iSec = typeMember("Line1/Mixer1.Secret", "Secret", Identifiers.Double, 42.0);
            mixer1.addComponent(iRpm);
            mixer1.addComponent(iTemp);
            mixer1.addComponent(iRun);
            mixer1.addComponent(iSec);
        }

        /**
         * WeldControllerType ObjectType (ns=2;s=WeldControllerType): a weld controller's members
         * (WeldCurrent, WeldTime, ElectrodeForce), each with an EURange engineering-range property.
         * Mirrors {@link #createMixerType()} — exposed so the northbound app can browse the TYPE to
         * derive a canonical spec definition for the downstream runtime conformance gate.
         */
        private void createWeldType() {
            UaObjectTypeNode weldType = new UaObjectTypeNode.UaObjectTypeNodeBuilder(getNodeContext())
                    .setNodeId(newNodeId("WeldControllerType"))
                    .setBrowseName(newQualifiedName("WeldControllerType"))
                    .setDisplayName(LocalizedText.english("WeldControllerType"))
                    .setIsAbstract(false)
                    .buildAndAdd();
            // WeldControllerType is-subtype-of BaseObjectType (inverse HasSubtype); a browser walks this up.
            weldType.addReference(new Reference(weldType.getNodeId(), Identifiers.HasSubtype,
                    Identifiers.BaseObjectType.expanded(), false));

            UaVariableNode current = typeMember("WeldControllerType.WeldCurrent", "WeldCurrent", Identifiers.Double, 0.0);
            UaVariableNode time = typeMember("WeldControllerType.WeldTime", "WeldTime", Identifiers.Double, 0.0);
            UaVariableNode force = typeMember("WeldControllerType.ElectrodeForce", "ElectrodeForce", Identifiers.Double, 0.0);
            weldType.addComponent(current);
            weldType.addComponent(time);
            weldType.addComponent(force);
            attachEuRange(current, "WeldControllerType.WeldCurrent.EURange", 0.0, 12.0);
            attachEuRange(time, "WeldControllerType.WeldTime.EURange", 0.0, 500.0);
            attachEuRange(force, "WeldControllerType.ElectrodeForce.EURange", 0.0, 6.0);
        }

        /**
         * BodyShop/Weld1: a concrete weld controller instance typed by WeldControllerType, browsable
         * under the Objects folder, with its three members seeded to static values. ElectrodeForce
         * seeds to 2.5 (below the 3.0 weld-lobe threshold) so the downstream runtime gate's
         * composition case triggers. Mirrors {@link #createMixerInstance()}.
         */
        private void createWeldInstance() {
            UaObjectNode weld1 = new UaObjectNode.UaObjectNodeBuilder(getNodeContext())
                    .setNodeId(newNodeId("BodyShop/Weld1"))
                    .setBrowseName(newQualifiedName("Weld1"))
                    .setDisplayName(LocalizedText.english("Weld1"))
                    .setTypeDefinition(newNodeId("WeldControllerType"))
                    .buildAndAdd();
            // Browsable under the Objects folder (inverse Organizes).
            weld1.addReference(new Reference(weld1.getNodeId(), Identifiers.Organizes,
                    Identifiers.ObjectsFolder.expanded(), false));
            UaVariableNode iCurrent = typeMember("BodyShop/Weld1.WeldCurrent", "WeldCurrent", Identifiers.Double, 6.0);
            UaVariableNode iTime = typeMember("BodyShop/Weld1.WeldTime", "WeldTime", Identifiers.Double, 200.0);
            UaVariableNode iForce = typeMember("BodyShop/Weld1.ElectrodeForce", "ElectrodeForce", Identifiers.Double, 2.5);
            weld1.addComponent(iCurrent);
            weld1.addComponent(iTime);
            weld1.addComponent(iForce);
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
