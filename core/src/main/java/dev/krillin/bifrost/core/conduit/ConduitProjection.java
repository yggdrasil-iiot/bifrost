package dev.krillin.bifrost.core.conduit;

import java.util.List;

/**
 * The governed conduits a registry implies: the edge, and the equipment it is the only permitted
 * writer of.
 *
 * <p><b>The equipment-to-address binding is declared, not discovered.</b> No byte on the wire says
 * that 10.10.10.10 is Line1-Mixer, and nothing in the governed registry records an address either.
 * It is the one input this seam cannot derive, it belongs to the operator, and the emitted document
 * says so in its own header rather than letting a later reader take it for a measured fact.
 */
public record ConduitProjection(String edgeAddress, List<GovernedEquipment> equipment) {

    /** The peer id the edge is given in the projected document. */
    public static final String EDGE_PEER_ID = "heimdall-edge";

    /**
     * Every protocol Huginn decodes, INCLUDING ones the edge does not speak.
     *
     * <p>The claim is "only the edge may write this equipment". Over a protocol the edge does not
     * speak its rule is never exercised and costs nothing, while every other host's write to that
     * equipment becomes a violation -- which is the finding the seam exists to produce. Declaring
     * only the protocol the edge happens to use would silently exempt the rest, and the bypass this
     * looks for is by nature over a protocol the edge is not on.
     */
    public static final List<String> DECODABLE_PROTOCOLS = List.of("MODBUS_TCP", "S7COMM");

    public ConduitProjection {
        equipment = List.copyOf(equipment);
    }

    /** One governed equipment and the address an operator says it answers on. */
    public record GovernedEquipment(String ref, String address) {}
}
