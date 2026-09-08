package dev.krillin.bifrost.core.command;

/**
 * Result of verifying a command segment's hash chain. Intact => {@code brokenIndex} and {@code rule}
 * are null; on a break, the FIRST break's zero-based index and rule slug.
 *
 * <p>{@code unparseable} is its own outcome rather than an exception: two unsynchronized appends can
 * interleave into a malformed line, and a verifier that dies in the JSON parser reports a crash
 * where it should report a finding.
 */
public record CommandChainVerdict(boolean intact, Integer brokenIndex, String rule) {
    public static CommandChainVerdict whole() { return new CommandChainVerdict(true, null, null); }
    public static CommandChainVerdict broken(int index, String rule) {
        return new CommandChainVerdict(false, index, rule);
    }
    public static CommandChainVerdict unparseable(int index) {
        return new CommandChainVerdict(false, index, "command.chain.unparseable-line");
    }
}
