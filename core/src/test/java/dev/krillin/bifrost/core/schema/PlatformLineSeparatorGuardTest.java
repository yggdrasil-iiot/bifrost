package dev.krillin.bifrost.core.schema;

import org.junit.jupiter.api.Test;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.*;

/** No production source in the reactor may write the platform line separator: the same input would then be
 *  CRLF bytes on Windows and LF on Linux, and Bifrost hashes and signs file bytes. Pretty JSON goes through
 *  {@link JsonMapperFactory#prettyWriter}. Line-separated text appends '\n' itself. */
class PlatformLineSeparatorGuardTest {
    static final List<String> FORBIDDEN = List.of(
            "writerWithDefaultPrettyPrinter", "INDENT_OUTPUT", "System.lineSeparator", "\"line.separator\"", "%n");

    @Test void noProductionSourceWritesThePlatformLineSeparator() throws Exception {
        Path reactor = Path.of("").toAbsolutePath().getParent();
        List<Path> roots = new ArrayList<>();
        try (Stream<Path> modules = Files.list(reactor)) {
            modules.map(m -> m.resolve("src/main/java")).filter(Files::isDirectory).forEach(roots::add);
        }
        assertTrue(roots.size() >= 4, "expected core, gates, heimdall and sim under " + reactor + ", found " + roots);
        List<String> hits = new ArrayList<>();
        int scanned = 0;
        for (Path root : roots) {
            try (Stream<Path> files = Files.walk(root)) {
                for (Path f : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                    scanned++;
                    List<String> lines = Files.readAllLines(f);
                    for (int i = 0; i < lines.size(); i++)
                        for (String token : FORBIDDEN)
                            if (lines.get(i).contains(token)) hits.add(reactor.relativize(f) + ":" + (i + 1) + " " + token);
                }
            }
        }
        assertTrue(scanned > 100, "the scan must actually read the sources, read " + scanned);
        assertEquals(List.of(), hits);
    }
}
