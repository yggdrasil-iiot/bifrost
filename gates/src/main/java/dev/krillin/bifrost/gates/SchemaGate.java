package dev.krillin.bifrost.gates;

import dev.krillin.bifrost.core.schema.CompatMode;
import dev.krillin.bifrost.core.schema.CompatibilityChecker;
import dev.krillin.bifrost.core.schema.DefinitionStore;
import dev.krillin.bifrost.core.schema.UdtDefinition;
import dev.krillin.bifrost.core.schema.Verdict;
import dev.krillin.bifrost.core.schema.Violation;

import java.nio.file.Path;
import java.util.Optional;

/**
 * Pre-deployment schema gate for CI. Exit codes: 0 = compatible (or new registration),
 * 1 = violations (blocked), 2 = error or bad usage.
 * Usage: SchemaGate &lt;registryDir&gt; &lt;proposedJson&gt; [--promote]
 */
public final class SchemaGate {

    public static void main(String[] args) { System.exit(run(args)); }

    public static int run(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: SchemaGate <registryDir> <proposedJson> [--promote]");
            return 2;
        }
        boolean promote = args.length > 2 && "--promote".equals(args[2]);
        try {
            DefinitionStore store = new DefinitionStore(Path.of(args[0]));
            CompatMode mode = store.policyMode();
            UdtDefinition proposed = store.load(Path.of(args[1]));
            Optional<UdtDefinition> current = store.latest(proposed.templateRef());

            if (current.isEmpty()) {
                System.out.println("[GATE] new templateRef '" + proposed.templateRef() + "' " + proposed.version() + " — initial registration allowed ✅");
                if (promote) { store.promote(proposed); System.out.println("[GATE] promoted to registry"); }
                return 0;
            }

            Verdict verdict = new CompatibilityChecker().check(current.get(), proposed, mode);
            System.out.println("[GATE] ref=" + proposed.templateRef() + " mode=" + mode
                    + " registered=" + current.get().version() + " proposed=" + proposed.version());
            if (verdict.compatible()) {
                System.out.println("[GATE] PASS ✅");
                if (promote) { store.promote(proposed); System.out.println("[GATE] promoted to registry"); }
                return 0;
            }
            System.out.println("[GATE] FAIL ❌ — violations:");
            for (Violation v : verdict.violations()) System.out.println("  - [" + v.rule() + "] " + v.detail());
            return 1;
        } catch (Exception e) {
            System.err.println("[GATE] error: " + e.getMessage());
            return 2;
        }
    }
}
