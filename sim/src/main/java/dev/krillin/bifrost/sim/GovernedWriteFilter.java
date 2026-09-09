package dev.krillin.bifrost.sim;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;

import org.eclipse.milo.opcua.sdk.server.Session;
import org.eclipse.milo.opcua.sdk.server.identity.Identity;
import org.eclipse.milo.opcua.sdk.server.nodes.filters.AttributeFilter;
import org.eclipse.milo.opcua.sdk.server.nodes.filters.AttributeFilterContext;
import org.eclipse.milo.opcua.stack.core.AttributeId;
import org.eclipse.milo.opcua.stack.core.types.builtin.unsigned.Unsigned;

/**
 * Makes the controlled nodes writable only by the governed identity, and read-only for every other
 * session. This is the mechanism {@code docs/ENTERPRISE.md} §12 names as "server-side write
 * permission", and it is the half of write-path exclusivity that lives on the server.
 *
 * <p><b>Why a UserAccessLevel filter and not an AccessController.</b> Milo 1.0 has exactly the right
 * interface — {@code AccessController.checkWriteAccess(Session, List<WriteValue>)} — and no way to
 * install one: {@code OpcUaServer} exposes {@code getAccessController()} with no setter and
 * {@code OpcUaServerConfig} has no property for it. What the default controller does consult is the
 * node's {@code UserAccessLevel}, through a session-scoped read that passes down this filter chain.
 * Do not go looking for the setter; it is not there.
 *
 * <p><b>An absent session is an internal read, not an anonymous one.</b> The filter chain has
 * session-less overloads and the sim's own {@code setValue(...)} calls take them, so an empty
 * {@code getSession()} must NOT be treated as deny — that would break the sim writing its own
 * ApplyDone. Deny applies to a session that is present and not governed.
 *
 * <p><b>Read stays open to everyone, deliberately.</b> A plant needs read-only clients — historians,
 * HMIs — and locking them out is not what write-path exclusivity means. Only the write bit moves.
 */
public final class GovernedWriteFilter implements AttributeFilter {

    /** OPC-UA access level bits: 1 = CurrentRead, 2 = CurrentWrite. */
    private static final int READ_ONLY = 1;
    private static final int READ_WRITE = 3;

    private final String governedThumbprint;

    public GovernedWriteFilter(String governedThumbprint) {
        this.governedThumbprint = governedThumbprint;
    }

    @Override
    public Object getAttribute(AttributeFilterContext ctx, AttributeId attributeId) {
        if (attributeId != AttributeId.UserAccessLevel) {
            return ctx.getAttribute(attributeId);
        }
        // Empty session => an internal read by the sim itself, which must keep its own write access.
        if (ctx.getSession().isEmpty()) {
            return ctx.getAttribute(attributeId);
        }
        return Unsigned.ubyte(userAccessLevelFor(sessionThumbprint(ctx.getSession().get()),
                governedThumbprint));
    }

    /**
     * The decision, split out so it can be tested without a live {@code Session}.
     *
     * <p>Fails closed on an unconfigured governed thumbprint. That branch is not hypothetical: with
     * the sim told to require an identity but given no thumbprint to require, an
     * {@code Objects.equals(null, null)} implementation would grant write access to an
     * unauthenticated session — the exact inversion of this filter's purpose. No configured
     * thumbprint means nobody is governed, never everybody.
     *
     * @param sessionThumbprint  the thumbprint the session presented, or null if it presented none
     * @param governedThumbprint the thumbprints permitted to write, comma-separated (a trust list, so
     *                           a certificate renewal can overlap), or null/blank if unconfigured
     */
    static int userAccessLevelFor(String sessionThumbprint, String governedThumbprint) {
        if (governedThumbprint == null || governedThumbprint.isBlank()) {
            return READ_ONLY;
        }
        if (sessionThumbprint == null || sessionThumbprint.isBlank()) {
            return READ_ONLY;
        }
        // A comma-separated LIST, because a real server's trust list is one. This is not a
        // convenience: a self-signed certificate cannot be renewed without changing its thumbprint,
        // so a single-valued trust list makes every renewal a cutover with no overlap -- the server
        // stops trusting the edge at the exact moment the edge starts presenting the new certificate.
        // The overlap window is the only reason a renewal does not stop the line.
        return isTrusted(sessionThumbprint, governedThumbprint) ? READ_WRITE : READ_ONLY;
    }

    /** Whether a presented thumbprint appears in the comma-separated trust list. Fails closed. */
    static boolean isTrusted(String presented, String trustList) {
        if (trustList == null || trustList.isBlank() || presented == null || presented.isBlank()) {
            return false;
        }
        String p = presented.trim();
        for (String permitted : trustList.split(",")) {
            if (!permitted.isBlank() && p.equalsIgnoreCase(permitted.trim())) {
                return true;
            }
        }
        return false;
    }

    /** The thumbprint of the certificate this session authenticated with, or null if it used none. */
    private static String sessionThumbprint(Session session) {
        Identity id = session.getIdentity();
        if (!(id instanceof Identity.X509UserIdentity x509)) {
            return null;   // anonymous or username: not the governed identity
        }
        return thumbprintOf(x509.getCertificate());
    }

    /** Lowercase hex SHA-1 of the encoded certificate — the OPC-UA thumbprint. */
    static String thumbprintOf(X509Certificate cert) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-1").digest(cert.getEncoded());
            StringBuilder sb = new StringBuilder(d.length * 2);
            for (byte b : d) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            // A certificate whose thumbprint cannot be computed is not the governed one.
            return null;
        }
    }
}
