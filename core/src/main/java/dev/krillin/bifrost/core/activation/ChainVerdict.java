package dev.krillin.bifrost.core.activation;

/** Result of verifying a ledger's hash chain. intact => brokenIndex and rule are null; on a break,
 *  the FIRST break's zero-based index and rule slug. */
public record ChainVerdict(boolean intact, Integer brokenIndex, String rule) {
    // NOTE: the "all good" factory is whole(), NOT intact() — a record auto-generates the accessor
    // intact(), so a static intact() factory is an override-equivalent name clash and will NOT compile.
    public static ChainVerdict whole()  { return new ChainVerdict(true, null, null); }
    public static ChainVerdict broken(int index, String rule) { return new ChainVerdict(false, index, rule); }
}
