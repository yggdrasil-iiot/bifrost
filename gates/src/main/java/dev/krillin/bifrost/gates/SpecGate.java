package dev.krillin.bifrost.gates;

import dev.krillin.bifrost.core.schema.DefinitionStore;
import dev.krillin.bifrost.core.schema.JsonMapperFactory;
import dev.krillin.bifrost.core.schema.MasterSpec;
import dev.krillin.bifrost.core.schema.SpecConformanceChecker;
import dev.krillin.bifrost.core.schema.SpecVerdict;
import dev.krillin.bifrost.core.schema.UdtDefinition;
import dev.krillin.bifrost.core.schema.Violation;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Master-spec conformance gate for CI: checks that a {@link MasterSpec}'s setpoints are admissible
 * against the PINNED equipment {@link UdtDefinition} it targets (structural + type + range).
 * Loads the equipment def by path convention ({@code <registryDir>/udt/<equipmentRef>/<equipmentVersion>.json}),
 * NOT the latest. Exit codes: 0 = conformant (pass), 1 = violations (blocked), 2 = error or bad usage.
 * Usage: SpecGate &lt;registryDir&gt; &lt;masterSpecFile&gt;
 */
public final class SpecGate {

    public static void main(String[] args) { System.exit(run(args)); }

    public static int run(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: SpecGate <registryDir> <masterSpecFile>");
            return 2;
        }
        try {
            MasterSpec spec = JsonMapperFactory.create().readValue(Path.of(args[1]).toFile(), MasterSpec.class);
            Path defPath = Path.of(args[0]).resolve("udt")
                    .resolve(spec.equipmentRef()).resolve(spec.equipmentVersion() + ".json");
            if (!Files.exists(defPath)) {
                System.err.println("[GATE] error: equipment " + spec.equipmentRef() + "@"
                        + spec.equipmentVersion() + " not in registry");
                return 2;
            }
            UdtDefinition def = new DefinitionStore(Path.of(args[0])).load(defPath);

            SpecVerdict v = new SpecConformanceChecker().check(def, spec);
            System.out.println("[GATE] ref=" + spec.specRef()
                    + " equipment=" + spec.equipmentRef() + "@" + spec.equipmentVersion()
                    + " setpoints=" + spec.setpoints().size());
            if (v.conformant()) {
                System.out.println("[GATE] PASS ✅");
                return 0;
            }
            System.out.println("[GATE] FAIL ❌ — violations:");
            for (Violation viol : v.violations()) System.out.println("  - [" + viol.rule() + "] " + viol.detail());
            return 1;
        } catch (Exception e) {
            System.err.println("[GATE] error: " + e.getMessage());
            return 2;
        }
    }
}
