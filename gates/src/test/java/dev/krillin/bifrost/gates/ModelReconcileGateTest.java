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
 * The operator-facing command: compare a vendor's export against a governed definition.
 *
 * <p>Exit codes follow the house convention -- 0 agreed, 1 divergence found, 2 usage or input
 * error. The third is what most of these tests are about: every way of failing to READ one of the
 * two sides must be exit 2, because the alternatives are both wrong. Reporting agreement would hide
 * the fault, and reporting divergence would blame the vendor for a broken input.
 */
class ModelReconcileGateTest {

    private static final String GOVERNED = """
            {"templateRef":"WeldController-corp","version":"1.0.0","members":[
              {"name":"WeldCurrent","type":"Double","semanticId":"corp:weld/current",
               "range":{"low":0.0,"high":15.0}}
            ],"params":[],"conformsTo":null}""";

    private static final String VENDOR_AGREED = """
            {"name":"WeldController-corp","tags":[
              {"name":"WeldCurrent","dataType":"Float8","engLow":0,"engHigh":15,
               "semanticId":"corp:weld/current"}
            ]}""";

    private static final String VENDOR_DRIFTED = """
            {"name":"WeldController-corp","tags":[
              {"name":"WeldCurrent","dataType":"Int4","engLow":0,"engHigh":15,
               "semanticId":"corp:weld/current"}
            ]}""";

    private static Path registry(Path reg) throws Exception {
        Path f = reg.resolve("udt").resolve("WeldController-corp").resolve("1.0.0.json");
        Files.createDirectories(f.getParent());
        Files.writeString(f, GOVERNED);
        return reg;
    }

    private static Path vendorFile(Path dir, String body) throws Exception {
        Path f = dir.resolve("vendor.json");
        Files.writeString(f, body);
        return f;
    }

    private record Run(int code, String out) {
    }

    private static Run run(String... args) {
        PrintStream saved = System.out;
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int code;
        try {
            System.setOut(new PrintStream(buf, true, StandardCharsets.UTF_8));
            code = ModelReconcileGate.run(args);
        } finally {
            System.setOut(saved);
        }
        return new Run(code, buf.toString(StandardCharsets.UTF_8));
    }

    private static String[] args(Path reg, Path vendor, String... extra) {
        String[] base = {reg.toString(), "WeldController-corp", "1.0.0",
                "--vendor", vendor.toString(), "--adapter", "ignition"};
        String[] all = new String[base.length + extra.length];
        System.arraycopy(base, 0, all, 0, base.length);
        System.arraycopy(extra, 0, all, base.length, extra.length);
        return all;
    }

    // ----- the two real outcomes -----

    @Test void an_agreeing_export_exits_zero(@TempDir Path reg, @TempDir Path dir) throws Exception {
        registry(reg);
        Run r = run(args(reg, vendorFile(dir, VENDOR_AGREED)));
        assertEquals(0, r.code(), r.out());
        assertTrue(r.out().contains("AGREED"), r.out());
        assertTrue(r.out().contains("per-object"), "the remediation unit must be reported: " + r.out());
    }

    @Test void a_divergent_export_exits_one_and_names_the_rule(@TempDir Path reg, @TempDir Path dir)
            throws Exception {
        registry(reg);
        Run r = run(args(reg, vendorFile(dir, VENDOR_DRIFTED)));
        assertEquals(1, r.code(), r.out());
        assertTrue(r.out().contains("vendor.member.type-mismatch"), r.out());
        assertTrue(r.out().contains("WeldCurrent"), r.out());
    }

    /** Granularity is the product's property, so the CLI takes it and reports what it implies. */
    @Test void whole_set_reports_the_same_finding_and_a_different_unit(@TempDir Path reg,
            @TempDir Path dir) throws Exception {
        registry(reg);
        Run r = run(args(reg, vendorFile(dir, VENDOR_DRIFTED), "--granularity", "whole-set"));
        assertEquals(1, r.code(), r.out());
        assertTrue(r.out().contains("vendor.member.type-mismatch"), r.out());
        assertTrue(r.out().contains("whole-set"), r.out());
    }

    // ----- every way of failing to read a side is exit 2 -----

    /**
     * The one most likely to be got wrong. "The vendor has no copy" is a finding an operator must
     * see; silently reporting agreement would be the worst possible answer.
     */
    @Test void a_missing_vendor_export_is_an_error_not_agreement(@TempDir Path reg, @TempDir Path dir)
            throws Exception {
        registry(reg);
        Run r = run(args(reg, dir.resolve("nope.json")));
        assertEquals(2, r.code(), r.out());
        assertFalse(r.out().contains("AGREED"), r.out());
        assertTrue(r.out().contains("vendor.export.absent"), r.out());
    }

    @Test void a_malformed_vendor_export_is_an_error(@TempDir Path reg, @TempDir Path dir)
            throws Exception {
        registry(reg);
        Run r = run(args(reg, vendorFile(dir, "not json at all")));
        assertEquals(2, r.code(), r.out());
        assertFalse(r.out().contains("AGREED"));
    }

    /**
     * An empty governed side would report every vendor member as unexpected -- a long, confident,
     * meaningless finding list. Fail closed instead.
     */
    @Test void an_unregistered_governed_ref_is_an_error_not_a_wall_of_findings(@TempDir Path reg,
            @TempDir Path dir) throws Exception {
        registry(reg);
        Run r = run(reg.toString(), "NoSuchTemplate", "1.0.0",
                "--vendor", vendorFile(dir, VENDOR_AGREED).toString(), "--adapter", "ignition");
        assertEquals(2, r.code(), r.out());
        assertTrue(r.out().contains("governed.definition.absent"), r.out());
        assertFalse(r.out().contains("vendor.member.unexpected"), r.out());
    }

    @Test void an_unknown_adapter_is_a_usage_error(@TempDir Path reg, @TempDir Path dir)
            throws Exception {
        registry(reg);
        Run r = run(reg.toString(), "WeldController-corp", "1.0.0",
                "--vendor", vendorFile(dir, VENDOR_AGREED).toString(), "--adapter", "kepware");
        assertEquals(2, r.code(), r.out());
    }

    /** An unrecognized granularity must not silently become the default. */
    @Test void an_unrecognized_granularity_is_a_usage_error(@TempDir Path reg, @TempDir Path dir)
            throws Exception {
        registry(reg);
        assertEquals(2, run(args(reg, vendorFile(dir, VENDOR_AGREED), "--granularity", "sometimes")).code());
    }

    @Test void missing_arguments_are_usage_errors(@TempDir Path reg) throws Exception {
        registry(reg);
        assertEquals(2, run().code());
        assertEquals(2, run(reg.toString()).code());
        assertEquals(2, run(reg.toString(), "WeldController-corp", "1.0.0").code());
    }

    @Test void granularity_defaults_to_per_object(@TempDir Path reg, @TempDir Path dir)
            throws Exception {
        registry(reg);
        Run r = run(args(reg, vendorFile(dir, VENDOR_AGREED)));
        assertEquals(0, r.code());
        assertTrue(r.out().contains("per-object"), r.out());
    }

    /** The dispatcher must route it, or the gate script cannot call it. */
    @Test void gates_cli_dispatches_model_reconcile(@TempDir Path reg, @TempDir Path dir)
            throws Exception {
        registry(reg);
        String[] a = args(reg, vendorFile(dir, VENDOR_AGREED));
        String[] withSub = new String[a.length + 1];
        withSub[0] = "model-reconcile";
        System.arraycopy(a, 0, withSub, 1, a.length);
        assertEquals(0, GatesCli.run(withSub));
    }
}
