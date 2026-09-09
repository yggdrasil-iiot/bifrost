package dev.krillin.bifrost.core.vendor;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

import com.fasterxml.jackson.databind.JsonNode;

import dev.krillin.bifrost.core.schema.JsonMapperFactory;

/**
 * A vendor model read from an export on disk -- the only source this round builds.
 *
 * <p><b>The fetch is not built, and the file is not a stand-in for it.</b> A Composer export, an
 * Ignition {@code tags/export} and a Kepware {@code GET} all produce a file, and {@code ADOPTION.md}
 * §2 asks for precisely this: read the vendor's copy back, read-only, the same way the traffic side
 * is handled. It is structurally what Huginn does with a pcap -- the artifact is handed over, the
 * tool is offline, and nothing it does can reach the plant.
 */
public final class FileVendorModelSource implements VendorModelSource {

    private final VendorCapability capability;
    private final Path export;

    public FileVendorModelSource(VendorCapability capability, Path export) {
        this.capability = capability;
        this.export = export;
    }

    @Override public VendorCapability capability() {
        return capability;
    }

    @Override public Optional<JsonNode> read(String ref) {
        if (!Files.isRegularFile(export)) {
            return Optional.empty();
        }
        try {
            return Optional.of(JsonMapperFactory.create().readTree(export.toFile()));
        } catch (IOException e) {
            // NEVER an empty tree: that would read as "the vendor has nothing" and produce a
            // finding for every governed member, which is confident and wrong.
            throw new VendorException("vendor.export.unreadable", export + " (" + e.getMessage() + ")");
        }
    }
}
