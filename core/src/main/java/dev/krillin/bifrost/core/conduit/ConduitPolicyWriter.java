package dev.krillin.bifrost.core.conduit;

import java.util.regex.Pattern;

/**
 * Writes a {@link ConduitProjection} as the {@code CommunicationPolicy} YAML Huginn already reads.
 *
 * <p>Written by hand rather than through a YAML library because {@code core} carries no YAML
 * dependency at compile scope, and adding one to emit twenty lines would be the wrong trade. The
 * cost of that choice is that quoting and validation are this class's job, so both are checked
 * here rather than assumed: a ref that cannot be represented safely is a coded refusal, never a
 * corrupt document.
 *
 * <p>Addresses must be IPv4 literals. A hostname would be accepted by Huginn's loader and then
 * never match a decoded packet, so the violation the rule exists to produce could never fire --
 * a vacuous rule, and one whose silence reads as "the plant is clean".
 */
public final class ConduitPolicyWriter {

    private static final String OCTET = "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";
    private static final Pattern IPV4 =
            Pattern.compile("^" + OCTET + "[.]" + OCTET + "[.]" + OCTET + "[.]" + OCTET + "$");

    public String write(ConduitProjection p, String registryPath) {
        if (p.equipment().isEmpty()) {
            throw new ConduitException("conduit.equipment.none",
                    "a document declaring an edge and no governed equipment governs nothing");
        }
        requireIpv4(p.edgeAddress(), "the edge");

        StringBuilder b = new StringBuilder();
        b.append("# Governed conduits projected from the Bifrost registry at ").append(registryPath).append('\n');
        b.append("# Produced by: gates conduit-project. Bifrost enforces nothing here -- this is an\n");
        b.append("# artifact for Huginn to check the wire against.\n");
        b.append("#\n");
        b.append("# THE EQUIPMENT-TO-ADDRESS BINDING IS DECLARED, NOT DISCOVERED. Nothing on the wire\n");
        b.append("# says which address is which governed equipment; an operator asserted it.\n");
        b.append("#\n");
        b.append("# This is a FRAGMENT, not a complete site policy. It says who may WRITE the governed\n");
        b.append("# equipment. Bifrost does not know which HMIs and historians may legitimately read\n");
        b.append("# it, so merge this into the site's declaration -- used alone, deny-by-default will\n");
        b.append("# report every legitimate read as a violation.\n");
        b.append("version: 1\n\n");

        b.append("peers:\n");
        b.append("  - id: ").append(scalar(ConduitProjection.EDGE_PEER_ID)).append('\n');
        b.append("    address: ").append(p.edgeAddress()).append('\n');
        for (ConduitProjection.GovernedEquipment e : p.equipment()) {
            requireIpv4(e.address(), "equipment '" + e.ref() + "'");
            b.append("  - id: ").append(scalar(e.ref())).append('\n');
            b.append("    address: ").append(e.address()).append('\n');
        }

        b.append("\nallowed:\n");
        for (ConduitProjection.GovernedEquipment e : p.equipment()) {
            for (String protocol : ConduitProjection.DECODABLE_PROTOCOLS) {
                b.append("  - from: ").append(scalar(ConduitProjection.EDGE_PEER_ID)).append('\n');
                b.append("    to: ").append(scalar(e.ref())).append('\n');
                b.append("    protocol: ").append(protocol).append('\n');
                b.append("    access: [READ, WRITE]\n");
            }
        }
        return b.toString();
    }

    private static void requireIpv4(String address, String what) {
        if (address == null || !IPV4.matcher(address).matches()) {
            throw new ConduitException("conduit.address.not-ipv4",
                    what + " has address '" + address + "'. A hostname is accepted by the policy"
                    + " loader and then matches no decoded packet, so the finding could never fire");
        }
    }

    /** Quote a scalar, refusing anything a single-quoted YAML scalar cannot carry on one line. */
    private static String scalar(String v) {
        if (v == null || v.isEmpty()) {
            throw new ConduitException("conduit.equipment.unrepresentable", "an empty ref");
        }
        if (v.indexOf('\n') >= 0 || v.indexOf('\r') >= 0) {
            throw new ConduitException("conduit.equipment.unrepresentable",
                    // Escaped, so the refusal stays one readable line instead of breaking the log
                    // apart at exactly the character it is complaining about.
                    "ref '" + v.replace("\n", "<LF>").replace("\r", "<CR>") + "' spans lines");
        }
        return "'" + v.replace("'", "''") + "'";
    }
}
