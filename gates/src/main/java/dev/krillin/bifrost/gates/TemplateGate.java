package dev.krillin.bifrost.gates;

import dev.krillin.bifrost.core.conformance.ConformanceVerdict;
import dev.krillin.bifrost.core.conformance.TemplateConformanceChecker;
import dev.krillin.bifrost.core.schema.DefinitionStore;
import dev.krillin.bifrost.core.schema.JsonMapperFactory;
import dev.krillin.bifrost.core.schema.UdtDefinition;
import dev.krillin.bifrost.core.schema.Violation;

import java.nio.file.Path;
import java.util.Optional;

/**
 * site &#8872; enterprise conformance gate for CI. Loads the site {@link UdtDefinition}, reads its
 * {@code conformsTo="ref@version"} pointer, loads that enterprise template from
 * {@code <registryDir>/udt/<ref>/<version>.json}, and checks conformance (subtyping/Liskov —
 * the site may tighten ranges and extend, but not violate the envelope).
 * Exit codes: 0 = conformant (pass), 1 = violations (blocked), 2 = error or bad usage.
 * Usage: TemplateGate &lt;registryDir&gt; &lt;siteDefFile&gt;
 */
public final class TemplateGate {

    public static void main(String[] args) { System.exit(run(args)); }

    public static int run(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: TemplateGate <registryDir> <siteDefFile>");
            return 2;
        }
        Path registryDir = Path.of(args[0]);
        try {
            UdtDefinition site = JsonMapperFactory.create()
                    .readValue(Path.of(args[1]).toFile(), UdtDefinition.class);
            if (site.conformsTo() == null || !site.conformsTo().contains("@")) {
                System.err.println("[GATE] error: site def has no conformsTo=<ref>@<version>");
                return 2;
            }
            String[] rv = site.conformsTo().split("@", 2);
            Optional<UdtDefinition> tOpt = new DefinitionStore(registryDir).load(rv[0], rv[1]);
            if (tOpt.isEmpty()) {
                System.err.println("[GATE] error: enterprise template " + site.conformsTo() + " not in registry");
                return 2;
            }
            ConformanceVerdict verdict = new TemplateConformanceChecker().check(site, tOpt.get());
            System.out.println("[GATE] site=" + site.templateRef() + " conformsTo=" + site.conformsTo()
                    + " members=" + site.members().size());
            if (verdict.ok()) { System.out.println("[GATE] PASS"); return 0; }
            System.out.println("[GATE] FAIL - violations:");
            for (Violation viol : verdict.violations()) System.out.println("  - [" + viol.rule() + "] " + viol.detail());
            return 1;
        } catch (Exception e) {
            System.err.println("[GATE] error: " + e.getMessage());
            return 2;
        }
    }
}
