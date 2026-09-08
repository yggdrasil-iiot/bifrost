package dev.krillin.bifrost.sim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

    // ----- R5: the trust list holds more than one thumbprint -----

    /**
     * A self-signed certificate cannot be renewed without changing its thumbprint, so a
     * single-valued trust list makes every renewal a cutover with no overlap: the server stops
     * trusting the edge at the exact moment the edge starts presenting the new certificate. The
     * overlap is the only reason a renewal does not stop the line.
     */
    @Test void either_thumbprint_in_the_list_may_write() {
        String list = "aabb,ccdd";
        assertEquals(3, GovernedWriteFilter.userAccessLevelFor("aabb", list));
        assertEquals(3, GovernedWriteFilter.userAccessLevelFor("ccdd", list));
        assertEquals(1, GovernedWriteFilter.userAccessLevelFor("eeff", list),
                "a third certificate is still refused");
    }

    @Test void each_element_tolerates_whitespace_and_case() {
        assertEquals(3, GovernedWriteFilter.userAccessLevelFor("AABB", " aabb , ccdd "));
        assertEquals(3, GovernedWriteFilter.userAccessLevelFor(" ccdd ", "aabb,CCDD"));
    }

    @Test void an_empty_element_grants_nothing() {
        assertEquals(1, GovernedWriteFilter.userAccessLevelFor("", "aabb,,ccdd"));
        assertEquals(1, GovernedWriteFilter.userAccessLevelFor("   ", "aabb,,ccdd"));
    }

    @Test void an_unconfigured_list_still_fails_closed() {
        assertEquals(1, GovernedWriteFilter.userAccessLevelFor("aabb", null));
        assertEquals(1, GovernedWriteFilter.userAccessLevelFor("aabb", ""));
        assertEquals(1, GovernedWriteFilter.userAccessLevelFor("aabb", " , "));
    }

    /** isTrusted is shared with the session validator, so the two cannot drift apart. */
    @Test void isTrusted_is_the_same_decision() {
        assertTrue(GovernedWriteFilter.isTrusted("ccdd", "aabb,ccdd"));
        assertFalse(GovernedWriteFilter.isTrusted("eeff", "aabb,ccdd"));
        assertFalse(GovernedWriteFilter.isTrusted("aabb", null));
        assertFalse(GovernedWriteFilter.isTrusted(null, "aabb"));
    }
}
