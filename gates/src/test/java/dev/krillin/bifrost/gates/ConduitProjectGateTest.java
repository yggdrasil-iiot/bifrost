package dev.krillin.bifrost.gates;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Projecting the governed conduits for Huginn to check the wire against.
 *
 * <p>The registry lookup is what makes this a Bifrost command rather than a YAML templater. A
 * {@code --bind} naming equipment nobody governs would produce a confident policy asserting
 * governance that does not exist, and every violation it then reported would be meaningless.
 */
class ConduitProjectGateTest {

    private static final String DEF = """
            {"templateRef":"Line1-Mixer","version":"1.0.0","members":[
              {"name":"Rpm","type":"Double","semanticId":null,"range":{"low":0.0,"high":3000.0}}
            ],"params":[],"conformsTo":null}""";

    private static void govern(Path reg, String ref) throws Exception {
        Path f = reg.resolve("udt").resolve(ref).resolve("1.0.0.json");
        Files.createDirectories(f.getParent());
        Files.writeString(f, DEF.replace("Line1-Mixer", ref));
    }

    private record Run(int code, String out) {
    }

    private static Run run(String... args) {
        PrintStream saved = System.out;
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int code;
        try {
            System.setOut(new PrintStream(buf, true, StandardCharsets.UTF_8));
            code = ConduitProjectGate.run(args);
        } finally {
            System.setOut(saved);
        }
        return new Run(code, buf.toString(StandardCharsets.UTF_8));
    }

    // ----- the happy path -----

    @Test void it_prints_the_projection(@TempDir Path reg) throws Exception {
        govern(reg, "Line1-Mixer");
        Run r = run(reg.toString(), "--edge", "10.10.10.20", "--bind", "Line1-Mixer=10.10.10.10");
        assertEquals(0, r.code(), r.out());
        assertTrue(r.out().contains("version: 1"), r.out());
        assertTrue(r.out().contains("10.10.10.10"), r.out());
        assertTrue(r.out().contains("S7COMM"), r.out());
    }

    @Test void out_writes_the_document_to_a_file(@TempDir Path reg, @TempDir Path dir) throws Exception {
        govern(reg, "Line1-Mixer");
        Path out = dir.resolve("conduits.yaml");
        Run r = run(reg.toString(), "--edge", "10.10.10.20",
                "--bind", "Line1-Mixer=10.10.10.10", "--out", out.toString());
        assertEquals(0, r.code(), r.out());
        assertTrue(Files.readString(out).contains("MODBUS_TCP"));
    }

    @Test void several_binds_are_all_projected(@TempDir Path reg) throws Exception {
        govern(reg, "Line1-Mixer");
        govern(reg, "Line2-Welder");
        Run r = run(reg.toString(), "--edge", "10.10.10.20",
                "--bind", "Line1-Mixer=10.10.10.10", "--bind", "Line2-Welder=10.10.10.11");
        assertEquals(0, r.code(), r.out());
        assertTrue(r.out().contains("Line1-Mixer") && r.out().contains("Line2-Welder"), r.out());
    }

    // ----- the check that makes this a Bifrost command -----

    @Test void equipment_not_in_the_registry_is_refused(@TempDir Path reg, @TempDir Path dir)
            throws Exception {
        govern(reg, "Line1-Mixer");
        Path out = dir.resolve("conduits.yaml");
        Run r = run(reg.toString(), "--edge", "10.10.10.20",
                "--bind", "NoSuchEquipment=10.10.10.10", "--out", out.toString());
        assertEquals(2, r.code(), r.out());
        assertTrue(r.out().contains("conduit.equipment.ungoverned"), r.out());
        assertTrue(Files.notExists(out), "a refused projection must write nothing");
    }

    /** Refused before ANY of the document exists, so a partial write cannot be mistaken for one. */
    @Test void one_bad_bind_among_good_ones_refuses_the_whole_projection(@TempDir Path reg,
            @TempDir Path dir) throws Exception {
        govern(reg, "Line1-Mixer");
        Path out = dir.resolve("conduits.yaml");
        Run r = run(reg.toString(), "--edge", "10.10.10.20",
                "--bind", "Line1-Mixer=10.10.10.10", "--bind", "Ghost=10.10.10.11",
                "--out", out.toString());
        assertEquals(2, r.code(), r.out());
        assertTrue(Files.notExists(out));
    }

    // ----- bindings that would make a finding meaningless -----

    /** Two peer ids at one address make a violation ambiguous about which equipment was reached. */
    @Test void two_equipments_at_one_address_are_refused(@TempDir Path reg) throws Exception {
        govern(reg, "Line1-Mixer");
        govern(reg, "Line2-Welder");
        Run r = run(reg.toString(), "--edge", "10.10.10.20",
                "--bind", "Line1-Mixer=10.10.10.10", "--bind", "Line2-Welder=10.10.10.10");
        assertEquals(2, r.code(), r.out());
        assertTrue(r.out().contains("conduit.address.duplicate"), r.out());
    }

    /**
     * If the edge were the equipment it governs, its own permitted traffic and every bypass would
     * arrive at the same peer and the finding could never separate them.
     */
    @Test void the_edge_cannot_be_the_equipment_it_governs(@TempDir Path reg) throws Exception {
        govern(reg, "Line1-Mixer");
        Run r = run(reg.toString(), "--edge", "10.10.10.10", "--bind", "Line1-Mixer=10.10.10.10");
        assertEquals(2, r.code(), r.out());
        assertTrue(r.out().contains("conduit.address.edge-is-equipment"), r.out());
    }

    // ----- usage -----

    @Test void no_bind_is_a_usage_error_not_an_empty_policy(@TempDir Path reg) throws Exception {
        govern(reg, "Line1-Mixer");
        Run r = run(reg.toString(), "--edge", "10.10.10.20");
        assertEquals(2, r.code(), r.out());
        assertFalse(r.out().contains("version: 1"), "an empty policy must never be emitted: " + r.out());
    }

    @Test void a_malformed_bind_is_a_usage_error(@TempDir Path reg) throws Exception {
        govern(reg, "Line1-Mixer");
        for (String bad : java.util.List.of("Line1-Mixer", "=10.10.10.10", "Line1-Mixer=", "=")) {
            assertEquals(2, run(reg.toString(), "--edge", "10.10.10.20", "--bind", bad).code(),
                    "expected a usage error for --bind '" + bad + "'");
        }
    }

    @Test void a_missing_edge_is_a_usage_error(@TempDir Path reg) throws Exception {
        govern(reg, "Line1-Mixer");
        assertEquals(2, run(reg.toString(), "--bind", "Line1-Mixer=10.10.10.10").code());
        assertEquals(2, run().code());
    }

    @Test void a_non_ipv4_address_is_refused(@TempDir Path reg) throws Exception {
        govern(reg, "Line1-Mixer");
        Run r = run(reg.toString(), "--edge", "10.10.10.20", "--bind", "Line1-Mixer=plc.plant.local");
        assertEquals(2, r.code(), r.out());
        assertTrue(r.out().contains("conduit.address.not-ipv4"), r.out());
    }

    // ----- what the operator is told -----

    @Test void it_says_the_binding_is_declared_and_the_output_a_fragment(@TempDir Path reg)
            throws Exception {
        govern(reg, "Line1-Mixer");
        String out = run(reg.toString(), "--edge", "10.10.10.20",
                "--bind", "Line1-Mixer=10.10.10.10").out().toLowerCase(java.util.Locale.ROOT);
        assertTrue(out.contains("declared"), out);
        assertTrue(out.contains("fragment"), out);
    }

    @Test void gates_cli_dispatches_conduit_project(@TempDir Path reg) throws Exception {
        govern(reg, "Line1-Mixer");
        assertEquals(0, GatesCli.run(new String[]{"conduit-project", reg.toString(),
                "--edge", "10.10.10.20", "--bind", "Line1-Mixer=10.10.10.10"}));
    }
}
