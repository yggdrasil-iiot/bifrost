package dev.krillin.bifrost.core.schema;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

class SemVerTest {
    @Test void parse_threePartString() {
        SemVer v = SemVer.parse("1.2.3");
        assertEquals(1, v.major());
        assertEquals(2, v.minor());
        assertEquals(3, v.patch());
    }

    @Test void parse_rejectsNonThreePart() {
        assertThrows(IllegalArgumentException.class, () -> SemVer.parse("1.0"));
        assertThrows(IllegalArgumentException.class, () -> SemVer.parse("1.0.0.0"));
        assertThrows(IllegalArgumentException.class, () -> SemVer.parse("x.y.z"));
    }

    @Test void compareTo_ordersByMajorThenMinorThenPatch() {
        assertTrue(SemVer.parse("2.0.0").compareTo(SemVer.parse("1.9.9")) > 0);
        assertTrue(SemVer.parse("1.1.0").compareTo(SemVer.parse("1.0.9")) > 0);
        assertTrue(SemVer.parse("1.0.1").compareTo(SemVer.parse("1.0.0")) > 0);
        assertEquals(0, SemVer.parse("1.0.0").compareTo(SemVer.parse("1.0.0")));
    }

    @Test void toString_roundTrips() {
        assertEquals("1.2.3", SemVer.parse("1.2.3").toString());
    }
}
