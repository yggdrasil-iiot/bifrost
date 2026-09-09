package dev.krillin.bifrost.core.vendor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The vendor's copy of the model, as it actually arrives: a file.
 *
 * <p>A Composer export, an Ignition {@code tags/export} and a Kepware {@code GET} all produce one,
 * and {@code ADOPTION.md} §2 asks for exactly this posture -- read the vendor's copy back,
 * read-only, the same way the traffic side is handled. Nothing here reaches a running product.
 *
 * <p>The distinction the tests below are built around: <b>"the vendor has no copy" and "the export
 * is corrupt" are different answers.</b> Collapsing the second into the first would let a
 * truncated download read as an empty vendor model, which then reports every governed member as
 * missing -- a long, confident, wrong finding list.
 */
class FileVendorModelSourceTest {

    private static final String EXPORT = """
            {"name":"WeldController-corp","tags":[
              {"name":"WeldCurrent","dataType":"Float8","engLow":0,"engHigh":15}
            ]}""";

    private static VendorCapability kepwareLike() {
        return new VendorCapability("kepware", Granularity.PER_OBJECT, true, true);
    }

    @Test void it_reads_an_export_from_disk(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("export.json");
        Files.writeString(f, EXPORT);
        var src = new FileVendorModelSource(kepwareLike(), f);

        var tree = src.read("WeldController-corp");
        assertTrue(tree.isPresent());
        assertEquals("WeldController-corp", tree.get().path("name").asText());
        assertEquals(1, tree.get().path("tags").size());
    }

    /** A legitimate answer, and a different one from a corrupt export. */
    @Test void an_absent_file_is_empty_rather_than_an_error(@TempDir Path dir) throws Exception {
        var src = new FileVendorModelSource(kepwareLike(), dir.resolve("nope.json"));
        assertTrue(src.read("anything").isEmpty());
    }

    /**
     * The one that matters. An empty tree here would read as "the vendor has nothing" and produce a
     * finding for every governed member -- so a corrupt export must be loud instead.
     */
    @Test void a_malformed_export_is_a_coded_error_not_an_empty_tree(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("export.json");
        Files.writeString(f, "this is not json");
        var src = new FileVendorModelSource(kepwareLike(), f);

        VendorException ex = assertThrows(VendorException.class, () -> src.read("x"));
        assertTrue(ex.getMessage().startsWith("vendor.export.unreadable"), ex.getMessage());
    }

    @Test void the_capability_is_what_the_source_was_built_with(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("export.json");
        Files.writeString(f, EXPORT);

        var perObject = new FileVendorModelSource(kepwareLike(), f);
        assertEquals("kepware", perObject.capability().product());
        assertEquals(Granularity.PER_OBJECT, perObject.capability().granularity());
        assertTrue(perObject.capability().canWrite());

        var blob = new FileVendorModelSource(
                new VendorCapability("thingworx", Granularity.WHOLE_SET, true, false), f);
        assertEquals(Granularity.WHOLE_SET, blob.capability().granularity());
        assertFalse(blob.capability().canWrite());
    }

    /** Granularity constrains REMEDIATION, not reading -- a blob product exports perfectly well. */
    @Test void a_whole_set_source_still_reads(@TempDir Path dir) throws Exception {
        Path f = dir.resolve("export.json");
        Files.writeString(f, EXPORT);
        var blob = new FileVendorModelSource(
                new VendorCapability("thingworx", Granularity.WHOLE_SET, true, false), f);
        assertTrue(blob.read("WeldController-corp").isPresent());
    }
}
