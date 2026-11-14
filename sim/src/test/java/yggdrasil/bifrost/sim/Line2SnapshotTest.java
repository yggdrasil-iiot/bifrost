package yggdrasil.bifrost.sim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static yggdrasil.bifrost.sim.Line2NodeTest.NS;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.eclipse.milo.opcua.sdk.client.OpcUaClient;
import org.eclipse.milo.opcua.sdk.server.nodes.UaVariableNode;
import org.eclipse.milo.opcua.stack.core.AttributeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.DataValue;
import org.eclipse.milo.opcua.stack.core.types.builtin.NodeId;
import org.junit.jupiter.api.Test;

/**
 * The Line2 scan commits one snapshot: one timestamp, all 22 members, set in a fixed order
 * (stations, then each tool's five members contiguously), SourceTimestamp = ServerTimestamp = that
 * time. Successive snapshot timestamps strictly increase, even when the clock does not.
 */
class Line2SnapshotTest {

    @Test
    void everyScanRestampsAll22MembersWithOneSharedTimestamp() throws Exception {
        try (EmbeddedMiloSim sim = Line2NodeTest.quietSim().start()) {
            long initial = Line2NodeTest.storedValue(sim, Line2NodeTest.allMembers().get(0)).getSourceTime().getUtcTime();
            for (int scan = 0; scan < 3; scan++) {
                sim.scanNow();
                Set<Long> times = new HashSet<>();
                for (String m : Line2NodeTest.allMembers()) {
                    DataValue stored = Line2NodeTest.storedValue(sim, m);
                    assertEquals(stored.getSourceTime(), stored.getServerTime(), m);
                    times.add(stored.getSourceTime().getUtcTime());
                }
                assertEquals(1, times.size(), "one snapshot, one timestamp");
                long t = times.iterator().next();
                assertTrue(t > initial, "scan " + scan + " advanced the snapshot time");
                initial = t;
            }

            // And as a client sees it: one Read of all 22, with no scan in between, one source time.
            OpcUaClient client = SimStatusControlTest.connect();
            try {
                Set<Long> seen = new HashSet<>();
                for (DataValue dv : Line2NodeTest.readAll(client, Line2NodeTest.allMembers())) {
                    seen.add(dv.getSourceTime().getUtcTime());
                }
                assertEquals(Set.of(initial), seen);
            } finally {
                client.disconnect();
            }
        }
    }

    @Test
    void snapshotTimestampsStrictlyIncreaseWhenTheClockStandsStill() throws Exception {
        try (EmbeddedMiloSim sim = Line2NodeTest.quietSim().start()) {
            long initial = Line2NodeTest.storedValue(sim, Line2NodeTest.allMembers().get(0)).getSourceTime().getUtcTime();
            // A clock stuck in the past: every scan must still move forward by one tick.
            sim.namespace().setLine2Clock(() -> initial - 1_000_000L);
            sim.scanNow();
            assertEquals(initial + 1, snapshotTicks(sim));
            sim.scanNow();
            assertEquals(initial + 2, snapshotTicks(sim));
            // A clock that moves forward again is taken as it is.
            sim.namespace().setLine2Clock(() -> initial + 500L);
            sim.scanNow();
            assertEquals(initial + 500L, snapshotTicks(sim));
            // Equal to the previous snapshot is "not after": one tick later.
            sim.scanNow();
            assertEquals(initial + 501L, snapshotTicks(sim));
        }
    }

    @Test
    void nextSnapshotTicksIsTheClockOrOneTickAfterThePrevious() {
        assertEquals(200L, EmbeddedMiloSim.SimNamespace.nextSnapshotTicks(100L, 200L));
        assertEquals(101L, EmbeddedMiloSim.SimNamespace.nextSnapshotTicks(100L, 100L));
        assertEquals(101L, EmbeddedMiloSim.SimNamespace.nextSnapshotTicks(100L, 5L));
    }

    /** Stations first, then each tool's five members in one contiguous run. */
    @Test
    void aScanSetsTheMembersInTheFixedOrderWithEachToolContiguous() throws Exception {
        try (EmbeddedMiloSim sim = Line2NodeTest.quietSim().start()) {
            List<String> order = Collections.synchronizedList(new ArrayList<>());
            for (String m : Line2NodeTest.allMembers()) {
                node(sim, m).addAttributeObserver((node, attributeId, value) -> {
                    if (attributeId == AttributeId.Value) {
                        order.add(node.getNodeId().getIdentifier().toString());
                    }
                });
            }
            sim.scanNow();
            assertEquals(Line2NodeTest.allMembers(), order);
        }
    }

    static long snapshotTicks(EmbeddedMiloSim sim) throws Exception {
        Set<Long> times = new HashSet<>();
        for (String m : Line2NodeTest.allMembers()) {
            times.add(Line2NodeTest.storedValue(sim, m).getSourceTime().getUtcTime());
        }
        assertEquals(1, times.size());
        return times.iterator().next();
    }

    static UaVariableNode node(EmbeddedMiloSim sim, String id) {
        return (UaVariableNode) sim.namespace().getNodeManager().getNode(NodeId.parse(NS + id)).orElseThrow();
    }

    /**
     * The accepted items of one Write request reach the members in one scan. The test makes a
     * request slow on purpose - its first item's control sleeps in an observer - while the scheduler
     * scans every 5 ms; any scan that ran between the request's items would commit Torque=k with the
     * other four members still at k-1, and the observer on the tool's last member would see it.
     */
    @Test
    void theItemsOfOneWriteRequestAreCommittedInTheSameScan() throws Exception {
        String tool = "Line2/Station1/Nutrunner1";
        List<String> controls = new ArrayList<>();
        for (String m : Line2NodeTest.TOOL_MEMBERS) {
            controls.add(Line2ControlTest.valueControl(tool + "." + m));
        }
        try (EmbeddedMiloSim sim = new EmbeddedMiloSim(EmbeddedMiloSim.BIND_PORT, EmbeddedMiloSim.DEFAULT_BIND_HOST,
                false, null, 5).start()) {
            node(sim, controls.get(0)).addAttributeObserver((node, attributeId, value) -> {
                if (attributeId == AttributeId.Value) {
                    try {
                        Thread.sleep(40);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                }
            });
            List<String> torn = Collections.synchronizedList(new ArrayList<>());
            int[] scans = {0};
            node(sim, tool + ".VisitPresent").addAttributeObserver((node, attributeId, value) -> {
                if (attributeId != AttributeId.Value) {
                    return;
                }
                scans[0]++;
                int k = (int) (double) (Double) node(sim, tool + ".Torque").getValue().getValue().getValue();
                List<Object> seen = new ArrayList<>();
                for (String m : Line2NodeTest.TOOL_MEMBERS) {
                    seen.add(node(sim, tool + "." + m).getValue().getValue().getValue());
                }
                if (!seen.equals(expected(k))) {
                    torn.add(seen.toString());
                }
            });

            OpcUaClient client = SimStatusControlTest.connect();
            try {
                for (int k = 1; k <= 4; k++) {
                    List<Object> values = expected(k);
                    List<org.eclipse.milo.opcua.stack.core.types.builtin.Variant> variants = new ArrayList<>();
                    for (Object v : values) {
                        variants.add(new org.eclipse.milo.opcua.stack.core.types.builtin.Variant(v));
                    }
                    for (var r : Line2ControlTest.writeAll(client, controls, variants)) {
                        assertTrue(r.isGood(), r.toString());
                    }
                }
            } finally {
                client.disconnect();
            }
            sim.scanNow();
            assertEquals(expected(4), List.of(
                    node(sim, tool + ".Torque").getValue().getValue().getValue(),
                    node(sim, tool + ".Running").getValue().getValue().getValue(),
                    node(sim, tool + ".UnitId").getValue().getValue().getValue(),
                    node(sim, tool + ".VisitId").getValue().getValue().getValue(),
                    node(sim, tool + ".VisitPresent").getValue().getValue().getValue()));
            assertTrue(scans[0] > 4, "the scheduler scanned while the requests were in flight: " + scans[0]);
            assertEquals(List.of(), torn, "a scan committed part of a Write request");
        }
    }

    /** Snapshot k of the tool's five members; k = 0 is the startup defaults. */
    static List<Object> expected(int k) {
        return k == 0
                ? List.of(0.0, false, "", "", false)
                : List.of((double) k, k % 2 == 1, "U-" + k, "V-" + k, k % 2 == 0);
    }
}
