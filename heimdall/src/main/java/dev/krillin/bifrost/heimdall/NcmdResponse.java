package dev.krillin.bifrost.heimdall;

/**
 * The correlated response the bridge sends back over NDATA. Mirrors koshei's {@code NcmdResponse}
 * (SpbCodec): {@code cmdId} = the request payload uuid; {@code ok} = applied+confirmed; for a read,
 * {@code value}+{@code good} carry the read-back; {@code detail} is a human-readable explanation.
 * {@code value}/{@code good} are null for write/call responses.
 */
public record NcmdResponse(String cmdId, boolean ok, String value, Boolean good, String detail) {

    public static NcmdResponse apply(String cmdId, boolean ok, String detail) {
        return new NcmdResponse(cmdId, ok, null, null, detail);
    }

    public static NcmdResponse read(String cmdId, String value, boolean good) {
        return new NcmdResponse(cmdId, good, value, good, "read=" + value + " good=" + good);
    }
}
