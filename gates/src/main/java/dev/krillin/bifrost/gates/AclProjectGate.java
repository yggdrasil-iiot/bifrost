package dev.krillin.bifrost.gates;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import com.fasterxml.jackson.databind.ObjectMapper;

import dev.krillin.bifrost.core.acl.AclEntry;
import dev.krillin.bifrost.core.acl.AclMapperFactory;
import dev.krillin.bifrost.core.acl.BrokerAclProjector;
import dev.krillin.bifrost.core.acl.CommandPolicy;

/**
 * Emit the broker ACL implied by a command policy: {@code principal → NCMD topic PUBLISH}.
 *
 * <p><b>This produces an artifact. It does not make any broker enforce anything</b>, and the
 * distinction is the whole of what this class is honest about. The intended design has always been
 * a split — the broker decides <i>who may publish</i>, the edge decides <i>what may be commanded</i>
 * — and until now neither half was connected: the edge ignored {@code Rule.principal} and
 * {@link BrokerAclProjector} had no caller outside its own unit test. R1 connected the edge half
 * for real, with a verified signature. This is the other half, and it stops at a file.
 *
 * <p><b>Why it stops there.</b> HiveMQ CE ships no ACL engine, and this repository's
 * {@code docker-compose.yml} runs the bundled allow-all extension deliberately, because
 * {@code hivemq-ce} is the shared broker for twelve gates and the compose file says in as many
 * words that {@code up -d hivemq-ce} must keep starting only that. Turning allow-all off to enforce
 * a projected ACL would break every one of them unless a second profiled broker were added, and the
 * projected entries carry no MQTT username mapping in any case. So the delta over the previous state
 * is narrow and deliberate: a caller and an output, not enforcement.
 *
 * <p>Usage: {@code gates acl-project <policy.json> [--out <file>]} — prints to stdout without
 * {@code --out}. Exit 0 on success, 2 on usage or IO error.
 */
public final class AclProjectGate {

    public static int run(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: gates acl-project <policy.json> [--out <file>]");
            return 2;
        }
        Path policyPath = Path.of(args[0]);
        Path out = null;
        for (int i = 1; i < args.length - 1; i++) {
            if ("--out".equals(args[i])) {
                out = Path.of(args[i + 1]);
            }
        }
        try {
            ObjectMapper mapper = AclMapperFactory.create();
            CommandPolicy policy = mapper.readValue(policyPath.toFile(), CommandPolicy.class);
            List<AclEntry> acl = new BrokerAclProjector().project(policy);

            StringBuilder sb = new StringBuilder();
            for (AclEntry e : acl) {
                sb.append(mapper.writeValueAsString(e)).append('\n');
            }
            if (out != null) {
                Files.writeString(out, sb.toString(), StandardCharsets.UTF_8);
                System.out.println("[ACL-PROJECT] " + acl.size() + " entries -> " + out);
            } else {
                System.out.print(sb);
                System.out.println("[ACL-PROJECT] " + acl.size() + " entries (artifact only - no broker enforces this)");
            }
            return 0;
        } catch (Exception e) {
            System.err.println("[ACL-PROJECT] ERROR: " + e.getMessage());
            return 2;
        }
    }

    public static void main(String[] args) {
        System.exit(run(args));
    }

    private AclProjectGate() {
    }
}
