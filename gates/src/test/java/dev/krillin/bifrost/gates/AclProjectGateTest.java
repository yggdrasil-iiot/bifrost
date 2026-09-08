package dev.krillin.bifrost.gates;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The projection is an artifact, so what is testable is the artifact — that it is emitted, that it
 * carries the principal the policy names, and that a bad input fails loudly rather than writing an
 * empty file someone would later mistake for "no grants".
 */
class AclProjectGateTest {

    private static final String POLICY = """
        {"version":"1.0.0","rules":[
          {"id":"rpm","principal":"recipe-writer","target":{"group":"Bifrost:Line1","edge":"recipe-edge"},
           "command":"ns=2;s=Recipe/Rpm","constraint":{"type":"Double"}}
        ],"default":"deny"}""";

    private Path write(Path d, String name, String body) throws Exception {
        Path f = d.resolve(name);
        Files.writeString(f, body);
        return f;
    }

    @Test void projects_the_named_principal_to_its_ncmd_topic(@TempDir Path d) throws Exception {
        Path out = d.resolve("acl.jsonl");
        assertEquals(0, AclProjectGate.run(new String[]{
                write(d, "p.json", POLICY).toString(), "--out", out.toString() }));
        String written = Files.readString(out);
        assertTrue(written.contains("\"principal\":\"recipe-writer\""), written);
        assertTrue(written.contains("spBv1.0/Bifrost:Line1/NCMD/recipe-edge"), written);
        assertTrue(written.contains("PUBLISH"), written);
    }

    @Test void a_missing_policy_file_is_an_error_not_an_empty_artifact(@TempDir Path d) {
        assertEquals(2, AclProjectGate.run(new String[]{ d.resolve("nope.json").toString() }));
    }

    @Test void noArgs_returnsTwo() {
        assertEquals(2, AclProjectGate.run(new String[]{}));
    }
}
