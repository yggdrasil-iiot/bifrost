package dev.krillin.bifrost.core.conduit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

/**
 * The governed registry, projected into the vocabulary Huginn already reads.
 *
 * <p>The claim being projected is narrow and it is the one row 12 leaves open: <b>only the governed
 * edge may write this equipment.</b> Huginn can only check that over what it decodes, so the
 * document declares the edge's permission over EVERY decodable protocol -- including ones the edge
 * does not speak. Over those its rule is simply never exercised and costs nothing, while every other
 * host's write to that equipment becomes a violation, which is the finding the seam exists to
 * produce. Enumerating only the protocol the edge happens to use would silently exempt the others.
 *
 * <p>Tests assert against the PARSED document rather than a golden string, so reformatting the
 * emitter does not break them. YAML is written by hand because {@code core} has no YAML dependency
 * at compile scope, which is also why quoting and validation are tested here rather than trusted to
 * a library.
 */
class ConduitPolicyWriterTest {

    private static final String EDGE = "10.10.10.20";

    private static JsonNode parse(String yaml) throws Exception {
        return new ObjectMapper(new YAMLFactory()).readTree(yaml);
    }

    private static String write(ConduitProjection p) {
        return new ConduitPolicyWriter().write(p, "build/test-registry");
    }

    private static ConduitProjection one() {
        return new ConduitProjection(EDGE,
                List.of(new ConduitProjection.GovernedEquipment("Line1-Mixer", "10.10.10.10")));
    }

    // ----- shape -----

    @Test void one_equipment_yields_two_peers_and_one_rule_per_protocol() throws Exception {
        JsonNode doc = parse(write(one()));
        assertEquals(1, doc.get("version").asInt());
        assertEquals(2, doc.get("peers").size());
        assertEquals(ConduitProjection.DECODABLE_PROTOCOLS.size(), doc.get("allowed").size());

        JsonNode rule = doc.get("allowed").get(0);
        assertEquals("Line1-Mixer", rule.get("to").asText());
        assertEquals(List.of("READ", "WRITE"),
                List.of(rule.get("access").get(0).asText(), rule.get("access").get(1).asText()));
    }

    @Test void the_edge_peer_appears_once_across_several_equipments() throws Exception {
        JsonNode doc = parse(write(new ConduitProjection(EDGE, List.of(
                new ConduitProjection.GovernedEquipment("Line1-Mixer", "10.10.10.10"),
                new ConduitProjection.GovernedEquipment("Line2-Welder", "10.10.10.11")))));

        assertEquals(3, doc.get("peers").size(), "two equipments and ONE edge");
        assertEquals(2 * ConduitProjection.DECODABLE_PROTOCOLS.size(), doc.get("allowed").size());

        long edgePeers = 0;
        for (JsonNode p : doc.get("peers")) {
            if (EDGE.equals(p.get("address").asText())) edgePeers++;
        }
        assertEquals(1, edgePeers);
    }

    /** Every rule must name the edge as its source, or the projection is not saying what it claims. */
    @Test void every_rule_is_from_the_edge() throws Exception {
        JsonNode doc = parse(write(one()));
        for (JsonNode rule : doc.get("allowed")) {
            assertEquals(ConduitProjection.EDGE_PEER_ID, rule.get("from").asText());
        }
    }

    @Test void both_decodable_protocols_are_covered() throws Exception {
        JsonNode doc = parse(write(one()));
        StringBuilder seen = new StringBuilder();
        for (JsonNode rule : doc.get("allowed")) seen.append(rule.get("protocol").asText()).append(' ');
        assertTrue(seen.toString().contains("MODBUS_TCP"), seen.toString());
        assertTrue(seen.toString().contains("S7COMM"), seen.toString());
    }

    // ----- the document has to survive being written by hand -----

    /** A ref with YAML-significant characters must be quoted, not concatenated into a broken doc. */
    @Test void a_ref_needing_quoting_is_quoted() throws Exception {
        JsonNode doc = parse(write(new ConduitProjection(EDGE,
                List.of(new ConduitProjection.GovernedEquipment("Line1: Mixer #2", "10.10.10.10")))));
        assertEquals("Line1: Mixer #2", doc.get("peers").get(1).get("id").asText());
        assertEquals("Line1: Mixer #2", doc.get("allowed").get(0).get("to").asText());
    }

    /** A ref that cannot be represented safely is a coded refusal, never a corrupt document. */
    @Test void a_ref_that_cannot_be_made_safe_is_refused() {
        ConduitException ex = assertThrows(ConduitException.class,
                () -> write(new ConduitProjection(EDGE,
                        List.of(new ConduitProjection.GovernedEquipment("bad\nref", "10.10.10.10")))));
        assertTrue(ex.getMessage().startsWith("conduit.equipment.unrepresentable"), ex.getMessage());
    }

    /**
     * A hostname would be accepted by Huginn's loader and then never match a decoded packet, so the
     * finding it was written to produce could never fire. That is a vacuous rule, and refusing it
     * here is cheaper than an operator concluding the plant is clean.
     */
    @Test void an_address_that_is_not_an_ipv4_literal_is_refused() {
        for (String bad : List.of("plc-mixer.plant.local", "10.10.10", "10.10.10.256", "", "1.2.3.4.5")) {
            ConduitException ex = assertThrows(ConduitException.class,
                    () -> write(new ConduitProjection(EDGE,
                            List.of(new ConduitProjection.GovernedEquipment("Line1-Mixer", bad)))),
                    "expected refusal for '" + bad + "'");
            assertTrue(ex.getMessage().startsWith("conduit.address.not-ipv4"), ex.getMessage());
        }
    }

    @Test void the_edge_address_is_validated_too() {
        ConduitException ex = assertThrows(ConduitException.class,
                () -> write(new ConduitProjection("edge.plant.local",
                        List.of(new ConduitProjection.GovernedEquipment("Line1-Mixer", "10.10.10.10")))));
        assertTrue(ex.getMessage().startsWith("conduit.address.not-ipv4"), ex.getMessage());
    }

    /** A document declaring an edge and nothing else governs nothing, and would look like success. */
    @Test void an_empty_equipment_list_is_refused() {
        ConduitException ex = assertThrows(ConduitException.class,
                () -> write(new ConduitProjection(EDGE, List.of())));
        assertTrue(ex.getMessage().startsWith("conduit.equipment.none"), ex.getMessage());
    }

    // ----- the document says where it came from -----

    /**
     * The binding is the one input nothing on the wire can supply. The artifact has to say a human
     * asserted it, or a reader six months later takes it for a discovered fact.
     */
    @Test void the_header_names_the_registry_and_calls_the_binding_declared() {
        String yaml = write(one());
        assertTrue(yaml.startsWith("#"), "the document opens with its provenance:\n" + yaml);
        assertTrue(yaml.contains("build/test-registry"), yaml);
        assertTrue(yaml.toLowerCase(java.util.Locale.ROOT).contains("declared"), yaml);
        assertTrue(yaml.contains("gates conduit-project"),
                "the header must say what produced it: " + yaml);
    }

    /** It is a fragment: Bifrost does not know the legitimate readers, so it cannot declare them. */
    @Test void the_header_says_it_is_not_a_complete_site_policy() {
        String yaml = write(one());
        assertTrue(yaml.toLowerCase(java.util.Locale.ROOT).contains("fragment"), yaml);
    }
}
