package dev.krillin.bifrost.core.identity;

/** Result of the full authenticated verification. intact => brokenIndex and rule null; else the FIRST
 *  break's zero-based entry index (or -1 for a head-level fault) and the identity.* rule slug. */
public record SignedVerdict(boolean intact, Integer brokenIndex, String rule) {
    public static SignedVerdict whole() { return new SignedVerdict(true, null, null); }
    public static SignedVerdict broken(int index, String rule) { return new SignedVerdict(false, index, rule); }
}
