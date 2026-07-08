package dev.krillin.bifrost.core.schema;

/** Immutable major.minor.patch semantic version value object. */
public record SemVer(int major, int minor, int patch) implements Comparable<SemVer> {

    public static SemVer parse(String s) {
        String[] p = s.split("\\.");
        if (p.length != 3) throw new IllegalArgumentException("not a 3-part SemVer: " + s);
        try {
            return new SemVer(Integer.parseInt(p[0]), Integer.parseInt(p[1]), Integer.parseInt(p[2]));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("SemVer numeric parsing failed: " + s, e);
        }
    }

    @Override public int compareTo(SemVer o) {
        int c = Integer.compare(major, o.major); if (c != 0) return c;
        c = Integer.compare(minor, o.minor);     if (c != 0) return c;
        return Integer.compare(patch, o.patch);
    }

    @Override public String toString() { return major + "." + minor + "." + patch; }
}
