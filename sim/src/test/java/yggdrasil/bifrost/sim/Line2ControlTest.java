package yggdrasil.bifrost.sim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static yggdrasil.bifrost.sim.Line2NodeTest.NS;

import java.util.ArrayList;
import java.util.List;

import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.stack.core.AttributeId;
import org.eclipse.milo.opcua.stack.core.NodeIds;
import org.eclipse.milo.opcua.stack.core.StatusCodes;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.StatusCode;
import org.eclipse.milo.opcua.stack.core.types.builtin.Variant;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.UInteger;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned;
import org.eclipse.milo.opcua.stack.core.types.enumerated.BrowseDirection;
import org.eclipse.milo.opcua.stack.core.types.structured.ReferenceDescription;
import org.eclipse.milo.opcua.stack.core.types.structured.WriteValue;
import org.junit.jupiter.api.Test;

/**
 * The Line2 {@code Sim/} controls. Each of the 22 members has {@code Sim/<member>.Value} (the
 * member's DataType) and {@code Sim/<member>.StatusCode} (UInt32), writable anonymously, never
 * components of an instance. A control holds the last accepted requested setting; the live member
 * keeps its committed snapshot until the next scan, which commits every setting together. Settings
 * not written persist, and repeated writes before a scan are last-write-wins.
 */
class Line2ControlTest {

    static final String TORQUE = "Line2/Station1/Nutrunner1.Torque";
    static final long BAD_SENSOR_FAILURE = 0x808B0000L;
    static final long UNCERTAIN_LAST_USABLE = 0x40900000L;

    static String valueControl(String member) {
        return "Sim/" + member + ".Value";
    }

    static String statusControl(String member) {
        return "Sim/" + member + ".StatusCode";
    }

    @Test
    void everyMemberHasAValueAndAStatusControl() throws Exception {
        try (EmbeddedMiloSim sim = Line2NodeTest.quietSim().start()) {
            OpcUaClient client = SimStatusControlTest.connect();
            try {
                for (String m : Line2NodeTest.allMembers()) {
                    NodeId value = NodeId.parse(NS + valueControl(m));
                    assertEquals(Line2NodeTest.dataTypeOf(m), Line2NodeTest.attr(client, value, AttributeId.DataType), m);
                    assertEquals(Unsigned.ubyte(3), Line2NodeTest.attr(client, value, AttributeId.AccessLevel), m);
                    assertEquals(Unsigned.ubyte(3), Line2NodeTest.attr(client, value, AttributeId.UserAccessLevel), m);
                    assertEquals(Line2NodeTest.defaultOf(m), Line2NodeTest.attr(client, value, AttributeId.Value), m);

                    NodeId status = NodeId.parse(NS + statusControl(m));
                    assertEquals(NodeIds.UInt32, Line2NodeTest.attr(client, status, AttributeId.DataType), m);
                    assertEquals(Unsigned.ubyte(3), Line2NodeTest.attr(client, status, AttributeId.AccessLevel), m);
                    assertEquals(Unsigned.ubyte(3), Line2NodeTest.attr(client, status, AttributeId.UserAccessLevel), m);
                    assertEquals(Unsigned.uint(0), Line2NodeTest.attr(client, status, AttributeId.Value), m);
                }
            } finally {
                client.disconnect();
            }
        }
    }

    /** The controls model the sensor, not a governed setpoint, so the governed-write filter skips them. */
    @Test
    void controlsAreWritableAnonymouslyWhenIdentityIsRequiredButMembersAreNot() throws Exception {
        try (EmbeddedMiloSim sim = new EmbeddedMiloSim(EmbeddedMiloSim.BIND_PORT, EmbeddedMiloSim.DEFAULT_BIND_HOST,
                true, "aabb", EmbeddedMiloSim.MAX_SCAN_MS).start()) {
            OpcUaClient client = SimStatusControlTest.connect();
            try {
                assertEquals(Unsigned.ubyte(3), Line2NodeTest.attr(client,
                        NodeId.parse(NS + valueControl(TORQUE)), AttributeId.UserAccessLevel));
                assertTrue(write(client, valueControl(TORQUE), new Variant(5.0)).isGood());
                assertTrue(write(client, statusControl(TORQUE), new Variant(Unsigned.uint(BAD_SENSOR_FAILURE))).isGood());
                assertTrue(write(client, valueControl("Line2/Station2.UnitId"), new Variant("U-1")).isGood());
                assertFalse(write(client, TORQUE, new Variant(5.0)).isGood(), "live member refuses a write");
            } finally {
                client.disconnect();
            }
        }
    }

    @Test
    void directWritesToLiveMembersAreRefused() throws Exception {
        try (EmbeddedMiloSim sim = Line2NodeTest.quietSim().start()) {
            OpcUaClient client = SimStatusControlTest.connect();
            try {
                for (String m : Line2NodeTest.allMembers()) {
                    Object v = Line2NodeTest.defaultOf(m);
                    StatusCode result = write(client, m, new Variant(v));
                    assertFalse(result.isGood(), m + " accepted a direct write: " + result);
                }
            } finally {
                client.disconnect();
            }
        }
    }

    @Test
    void controlsAreNotComponentsOfAnyInstance() throws Exception {
        try (EmbeddedMiloSim sim = Line2NodeTest.quietSim().start()) {
            OpcUaClient client = SimStatusControlTest.connect();
            try {
                List<String> instances = new ArrayList<>(Line2NodeTest.STATIONS);
                instances.addAll(Line2NodeTest.TOOLS);
                instances.add("Line2");
                for (String i : instances) {
                    for (ReferenceDescription r : Line2NodeTest.browse(client, NodeId.parse(NS + i),
                            BrowseDirection.Both, NodeIds.References)) {
                        assertFalse(r.getNodeId().getIdentifier().toString().startsWith("Sim/"), i + " -> " + r.getNodeId());
                    }
                }
            } finally {
                client.disconnect();
            }
        }
    }

    @Test
    void aWriteIsStagedAndTakesEffectTogetherAtTheNextScan() throws Exception {
        try (EmbeddedMiloSim sim = Line2NodeTest.quietSim().start()) {
            OpcUaClient client = SimStatusControlTest.connect();
            try {
                assertTrue(write(client, valueControl(TORQUE), new Variant(12.5)).isGood());
                assertTrue(write(client, statusControl(TORQUE), new Variant(Unsigned.uint(BAD_SENSOR_FAILURE))).isGood());

                DataValue live = SimStatusControlTest.read(client, NS + TORQUE);
                assertEquals(0.0, live.getValue().getValue(), "live member keeps its snapshot until the scan");
                assertTrue(live.getStatusCode().isGood());
                assertEquals(12.5, SimStatusControlTest.read(client, NS + valueControl(TORQUE)).getValue().getValue(),
                        "a control reads back the requested setting");
                assertEquals(Unsigned.uint(BAD_SENSOR_FAILURE),
                        SimStatusControlTest.read(client, NS + statusControl(TORQUE)).getValue().getValue());

                sim.scanNow();
                DataValue committed = SimStatusControlTest.read(client, NS + TORQUE);
                assertEquals(12.5, committed.getValue().getValue());
                assertEquals(BAD_SENSOR_FAILURE, committed.getStatusCode().getValue());
            } finally {
                client.disconnect();
            }
        }
    }

    @Test
    void settingsNotWrittenPersistAcrossScans() throws Exception {
        try (EmbeddedMiloSim sim = Line2NodeTest.quietSim().start()) {
            OpcUaClient client = SimStatusControlTest.connect();
            try {
                String unit = "Line2/Station3.UnitId";
                assertTrue(write(client, valueControl(unit), new Variant("U-42")).isGood());
                sim.scanNow();
                sim.scanNow();
                assertEquals("U-42", SimStatusControlTest.read(client, NS + unit).getValue().getValue());

                assertTrue(write(client, statusControl(unit), new Variant(Unsigned.uint(UNCERTAIN_LAST_USABLE))).isGood());
                sim.scanNow();
                DataValue v = SimStatusControlTest.read(client, NS + unit);
                assertEquals("U-42", v.getValue().getValue(), "the value setting persisted");
                assertEquals(UNCERTAIN_LAST_USABLE, v.getStatusCode().getValue());
                sim.scanNow();
                assertEquals(UNCERTAIN_LAST_USABLE,
                        SimStatusControlTest.read(client, NS + unit).getStatusCode().getValue(), "the status persisted");
            } finally {
                client.disconnect();
            }
        }
    }

    @Test
    void repeatedWritesBeforeAScanAreLastWriteWins() throws Exception {
        try (EmbeddedMiloSim sim = Line2NodeTest.quietSim().start()) {
            OpcUaClient client = SimStatusControlTest.connect();
            try {
                for (double d : new double[] {1.0, 2.0, 3.0}) {
                    assertTrue(write(client, valueControl(TORQUE), new Variant(d)).isGood());
                }
                assertTrue(write(client, valueControl("Line2/Station1.VisitPresent"), new Variant(true)).isGood());
                assertTrue(write(client, valueControl("Line2/Station1.VisitPresent"), new Variant(false)).isGood());
                assertTrue(write(client, valueControl("Line2/Station1.VisitPresent"), new Variant(true)).isGood());
                sim.scanNow();
                assertEquals(3.0, SimStatusControlTest.read(client, NS + TORQUE).getValue().getValue());
                assertEquals(true, SimStatusControlTest.read(client, NS + "Line2/Station1.VisitPresent")
                        .getValue().getValue());
            } finally {
                client.disconnect();
            }
        }
    }

    @Test
    void statusMovesThroughBadUncertainAndGoodKeepingTheValue() throws Exception {
        try (EmbeddedMiloSim sim = Line2NodeTest.quietSim().start()) {
            OpcUaClient client = SimStatusControlTest.connect();
            try {
                String running = "Line2/Station2.Running";
                assertTrue(write(client, valueControl(running), new Variant(true)).isGood());
                for (long code : new long[] {BAD_SENSOR_FAILURE, UNCERTAIN_LAST_USABLE, 0L}) {
                    assertTrue(write(client, statusControl(running), new Variant(Unsigned.uint(code))).isGood());
                    sim.scanNow();
                    DataValue v = SimStatusControlTest.read(client, NS + running);
                    assertEquals(code, v.getStatusCode().getValue());
                    assertEquals(true, v.getValue().getValue());
                }
            } finally {
                client.disconnect();
            }
        }
    }

    /** One Write request with one item. */
    static StatusCode write(OpcUaClient client, String id, Variant value) throws Exception {
        return client.writeValues(List.of(NodeId.parse(NS + id)), List.of(new DataValue(value))).get(0);
    }

    /** One Write request carrying every given item, in order. */
    static List<StatusCode> writeAll(OpcUaClient client, List<String> ids, List<Variant> values) throws Exception {
        List<WriteValue> items = new ArrayList<>();
        for (int i = 0; i < ids.size(); i++) {
            items.add(new WriteValue(NodeId.parse(NS + ids.get(i)), AttributeId.Value.uid(), null,
                    new DataValue(values.get(i))));
        }
        return List.of(client.write(items).getResults());
    }

    // ----- validation: wrong DataType, null or array is Bad_TypeMismatch, before anything changes -----

    @Test
    void aWrongDataTypeANullOrAnArrayIsRejectedWithoutCoercion() throws Exception {
        try (EmbeddedMiloSim sim = Line2NodeTest.quietSim().start()) {
            OpcUaClient client = SimStatusControlTest.connect();
            try {
                Object[][] cases = {
                        {valueControl(TORQUE), new Variant(5)},                    // Int32 to Double: no coercion
                        {valueControl(TORQUE), new Variant(5.0f)},                 // Float to Double
                        {valueControl(TORQUE), new Variant("5.0")},
                        {valueControl(TORQUE), Variant.NULL_VALUE},
                        {valueControl(TORQUE), new Variant(new Double[] {1.0, 2.0})},
                        {valueControl("Line2/Station1.Running"), new Variant(1.0)},
                        {valueControl("Line2/Station1.Running"), new Variant("true")},
                        {valueControl("Line2/Station1.Running"), new Variant(new Boolean[] {true})},
                        {valueControl("Line2/Station1.UnitId"), new Variant(42)},
                        {valueControl("Line2/Station1.UnitId"), Variant.NULL_VALUE},
                        {valueControl("Line2/Station1.UnitId"), new Variant(new String[] {"a"})},
                        {statusControl(TORQUE), new Variant(5)},                   // Int32 to UInt32
                        {statusControl(TORQUE), new Variant(5L)},                  // Int64 to UInt32
                        {statusControl(TORQUE), Variant.NULL_VALUE},
                        {statusControl(TORQUE), new Variant(new UInteger[] {Unsigned.uint(0)})},
                };
                for (Object[] c : cases) {
                    StatusCode result = write(client, (String) c[0], (Variant) c[1]);
                    assertEquals(StatusCodes.Bad_TypeMismatch, result.getValue(),
                            c[0] + " <- " + c[1] + " gave " + result);
                }
            } finally {
                client.disconnect();
            }
        }
    }

    @Test
    void aRejectedWriteChangesNeitherTheRequestedNorThePendingSetting() throws Exception {
        try (EmbeddedMiloSim sim = Line2NodeTest.quietSim().start()) {
            OpcUaClient client = SimStatusControlTest.connect();
            try {
                assertTrue(write(client, valueControl(TORQUE), new Variant(7.0)).isGood());
                assertTrue(write(client, statusControl(TORQUE), new Variant(Unsigned.uint(BAD_SENSOR_FAILURE))).isGood());
                assertFalse(write(client, valueControl(TORQUE), new Variant(8)).isGood());
                assertFalse(write(client, valueControl(TORQUE), Variant.NULL_VALUE).isGood());
                assertFalse(write(client, statusControl(TORQUE), new Variant(0)).isGood());

                assertEquals(7.0, SimStatusControlTest.read(client, NS + valueControl(TORQUE)).getValue().getValue());
                assertEquals(Unsigned.uint(BAD_SENSOR_FAILURE),
                        SimStatusControlTest.read(client, NS + statusControl(TORQUE)).getValue().getValue());
                assertEquals(0.0, SimStatusControlTest.read(client, NS + TORQUE).getValue().getValue(),
                        "nothing reached the live member before the scan");

                sim.scanNow();
                DataValue v = SimStatusControlTest.read(client, NS + TORQUE);
                assertEquals(7.0, v.getValue().getValue());
                assertEquals(BAD_SENSOR_FAILURE, v.getStatusCode().getValue());
            } finally {
                client.disconnect();
            }
        }
    }

    /** Items are validated one by one: a bad item is refused, the good items of the same request land. */
    @Test
    void aRequestMixingGoodAndBadItemsAppliesOnlyTheGoodOnes() throws Exception {
        try (EmbeddedMiloSim sim = Line2NodeTest.quietSim().start()) {
            OpcUaClient client = SimStatusControlTest.connect();
            try {
                List<StatusCode> results = writeAll(client,
                        List.of(valueControl(TORQUE), valueControl("Line2/Station1/Nutrunner1.UnitId"),
                                valueControl("Line2/Station1/Nutrunner1.VisitId")),
                        List.of(new Variant(9.0), new Variant(5), new Variant("V-9")));
                assertTrue(results.get(0).isGood(), results.toString());
                assertEquals(StatusCodes.Bad_TypeMismatch, results.get(1).getValue(), results.toString());
                assertTrue(results.get(2).isGood(), results.toString());
                sim.scanNow();
                assertEquals(9.0, SimStatusControlTest.read(client, NS + TORQUE).getValue().getValue());
                assertEquals("", SimStatusControlTest.read(client, NS + "Line2/Station1/Nutrunner1.UnitId")
                        .getValue().getValue());
                assertEquals("V-9", SimStatusControlTest.read(client, NS + "Line2/Station1/Nutrunner1.VisitId")
                        .getValue().getValue());
            } finally {
                client.disconnect();
            }
        }
    }

    /** Mixer1's status controls keep their own (immediate) behaviour and are not Line2-validated. */
    @Test
    void mixer1StatusControlsStillApplyImmediately() throws Exception {
        try (EmbeddedMiloSim sim = Line2NodeTest.quietSim().start()) {
            OpcUaClient client = SimStatusControlTest.connect();
            try {
                SimStatusControlTest.write(client, SimStatusControlTest.TEMP_STATUS, BAD_SENSOR_FAILURE);
                assertEquals(BAD_SENSOR_FAILURE,
                        SimStatusControlTest.read(client, SimStatusControlTest.TEMP).getStatusCode().getValue());
            } finally {
                client.disconnect();
            }
        }
    }
}
