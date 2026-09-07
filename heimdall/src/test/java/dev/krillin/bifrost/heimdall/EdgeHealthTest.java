package dev.krillin.bifrost.heimdall;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class EdgeHealthTest {

    @Test
    void startsUnhealthyUntilBothLegsAreUp() {
        EdgeHealth h = new EdgeHealth();
        assertFalse(h.healthy(), "an edge that has connected to nothing is not healthy");
        h.brokerConnected();
        assertFalse(h.healthy(), "broker alone is not enough - the plant leg matters too");
        h.plantReachable();
        assertTrue(h.healthy());
    }

    @Test
    void anUnreachablePlantMakesTheEdgeUnhealthy() {
        EdgeHealth h = new EdgeHealth();
        h.brokerConnected();
        h.plantReachable();
        h.plantUnreachable();
        assertFalse(h.healthy(), "the edge cannot be healthy while it cannot see the plant");
        assertEquals(1, h.unreachableCount());
    }

    @Test
    void aRecoveredPlantMakesItHealthyAgain() {
        EdgeHealth h = new EdgeHealth();
        h.brokerConnected();
        h.plantUnreachable();
        h.plantReachable();
        assertTrue(h.healthy(), "recovery must be reported, or /healthz latches unhealthy forever");
    }

    @Test
    void countersSeparateTheThreeOutcomes() {
        EdgeHealth h = new EdgeHealth();
        h.applied(); h.applied(); h.denied(); h.plantUnreachable();
        assertEquals(2, h.appliedCount());
        assertEquals(1, h.deniedCount());
        assertEquals(1, h.unreachableCount());
        String body = h.report();
        assertTrue(body.contains("applied 2"), body);
        assertTrue(body.contains("denied 1"), body);
        assertTrue(body.contains("plant_unreachable 1"), body);
    }
}
