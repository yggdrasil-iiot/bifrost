package dev.krillin.bifrost.sim;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

/**
 * The write-permission decision, tested on its two inputs rather than by constructing a Milo
 * {@code Session}. Read access is never in question here — only whether the session may write.
 */
class GovernedWriteFilterTest {

    @Test
    void anUnknownSessionGetsReadOnly() {
        assertEquals(1, GovernedWriteFilter.userAccessLevelFor(null, "aabb"));
        assertEquals(1, GovernedWriteFilter.userAccessLevelFor("ffff", "aabb"));
    }

    @Test
    void theGovernedThumbprintGetsReadWrite() {
        assertEquals(3, GovernedWriteFilter.userAccessLevelFor("aabb", "aabb"));
    }

    /** Case must not decide authorization: thumbprints are hex and both cases occur in the wild. */
    @Test
    void thumbprintComparisonIsCaseInsensitive() {
        assertEquals(3, GovernedWriteFilter.userAccessLevelFor("AABB", "aabb"));
        assertEquals(3, GovernedWriteFilter.userAccessLevelFor("aabb", "AABB"));
    }

    /**
     * The case that matters most. With {@code SIM_REQUIRE_IDENTITY=on} but no governed thumbprint
     * configured, an {@code Objects.equals(null, null)} implementation hands write access to an
     * unauthenticated session — the exact inversion of what this round is for. No configured
     * thumbprint means nobody is governed, never everybody.
     */
    @Test
    void anUnconfiguredGovernedThumbprintFailsClosed() {
        assertEquals(1, GovernedWriteFilter.userAccessLevelFor(null, null));
        assertEquals(1, GovernedWriteFilter.userAccessLevelFor("aabb", null));
        assertEquals(1, GovernedWriteFilter.userAccessLevelFor("aabb", "   "));
        assertEquals(1, GovernedWriteFilter.userAccessLevelFor(null, "  "));
    }
}
