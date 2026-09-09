package dev.krillin.bifrost.gates;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import com.fasterxml.jackson.databind.JsonNode;

import dev.krillin.bifrost.core.conformance.adapter.AasSubmodelAdapter;
import dev.krillin.bifrost.core.conformance.adapter.CfihosTemplateAdapter;
import dev.krillin.bifrost.core.conformance.adapter.IgnitionUdtAdapter;
import dev.krillin.bifrost.core.conformance.adapter.TemplateAdapter;
import dev.krillin.bifrost.core.schema.DefinitionStore;
import dev.krillin.bifrost.core.schema.UdtDefinition;
import dev.krillin.bifrost.core.schema.Violation;
import dev.krillin.bifrost.core.vendor.FileVendorModelSource;
import dev.krillin.bifrost.core.vendor.Granularity;
import dev.krillin.bifrost.core.vendor.ModelReconciler;
import dev.krillin.bifrost.core.vendor.ReconciliationVerdict;
import dev.krillin.bifrost.core.vendor.VendorCapability;
import dev.krillin.bifrost.core.vendor.VendorException;

/**
 * Compares a vendor's exported model against the governed definition and reports divergence.
 *
 * <p>{@code model-reconcile <reg> <ref> <version> --vendor <file> --adapter <ignition|cfihos|aas>
 * [--granularity per-object|whole-set]} &mdash; 0 agreed / 1 divergence / 2 usage or input error.
 *
 * <p><b>The fetch is not built.</b> The vendor's copy arrives as a FILE, which is what a Composer
 * export, an Ignition {@code tags/export} and a Kepware {@code GET} all produce, and what
 * {@code ADOPTION.md} §2 asks for: read the copy back, read-only, the same way the traffic side is
 * handled. Nothing here reaches a running product.
 *
 * <p>Every way of failing to READ one of the two sides is exit 2. Reporting agreement would hide
 * the fault; reporting divergence would blame the vendor for a broken input.
 */
public final class ModelReconcileGate {

    private static final String USAGE = "Usage: model-reconcile <reg> <ref> <version>"
            + " --vendor <file> --adapter <ignition|cfihos|aas>"
            + " [--granularity per-object|whole-set]";

    public static void main(String[] args) {
        System.exit(run(args));
    }

    public static int run(String[] args) {
        String vendorFile = null, adapterKind = null, granularityArg = "per-object";
        List<String> pos = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--vendor" -> vendorFile = (++i < args.length) ? args[i] : null;
                case "--adapter" -> adapterKind = (++i < args.length) ? args[i] : null;
                case "--granularity" -> granularityArg = (++i < args.length) ? args[i] : null;
                default -> pos.add(args[i]);
            }
        }
        if (pos.size() < 3 || vendorFile == null || adapterKind == null || granularityArg == null) {
            System.err.println(USAGE);
            return 2;
        }
        TemplateAdapter adapter = switch (adapterKind) {
            case "ignition" -> new IgnitionUdtAdapter();
            case "cfihos" -> new CfihosTemplateAdapter();
            case "aas" -> new AasSubmodelAdapter();
            default -> null;
        };
        if (adapter == null) {
            System.err.println("[GATE] error: unknown adapter kind '" + adapterKind
                    + "' (expected ignition|cfihos|aas)");
            return 2;
        }
        // An unrecognized granularity must NOT fall back to the default: it is the field that says
        // how a correction is applied, and quietly guessing it is how a blob product gets reported
        // as incrementally fixable.
        Granularity granularity = switch (granularityArg) {
            case "per-object" -> Granularity.PER_OBJECT;
            case "whole-set" -> Granularity.WHOLE_SET;
            default -> null;
        };
        if (granularity == null) {
            System.err.println("[GATE] error: unknown granularity '" + granularityArg
                    + "' (expected per-object|whole-set)");
            return 2;
        }

        Path reg = Path.of(pos.get(0));
        String ref = pos.get(1);
        String version = pos.get(2);
        try {
            Optional<UdtDefinition> governed = new DefinitionStore(reg).load(ref, version);
            // Fail closed. An empty governed side would report every vendor member as unexpected --
            // a long, confident, meaningless finding list.
            if (governed.isEmpty()) {
                System.out.println("[GATE] REFUSED:");
                System.out.println("  - [governed.definition.absent] " + ref + "@" + version
                        + " is not in the registry at " + reg);
                return 2;
            }
            var source = new FileVendorModelSource(
                    VendorCapability.readOnly(adapterKind, granularity), Path.of(vendorFile));
            Optional<JsonNode> tree = source.read(ref);
            if (tree.isEmpty()) {
                System.out.println("[GATE] REFUSED:");
                System.out.println("  - [vendor.export.absent] no export at " + vendorFile
                        + " - 'the vendor has no copy' is a finding, not a pass");
                return 2;
            }
            UdtDefinition vendorSide = adapter.adapt(tree.get(), ref, version);
            ReconciliationVerdict v = new ModelReconciler()
                    .reconcile(governed.get(), vendorSide, granularity);

            String unit = granularity == Granularity.PER_OBJECT ? "per-object" : "whole-set";
            if (v.agreed()) {
                System.out.println("[GATE] model-reconcile " + ref + "@" + version
                        + " vendor=" + adapterKind + " remediation=" + unit + " => AGREED");
                return 0;
            }
            System.out.println("[GATE] model-reconcile " + ref + "@" + version
                    + " vendor=" + adapterKind + " remediation=" + unit
                    + " => DIVERGED (" + v.findings().size() + ")");
            for (Violation f : v.findings()) {
                System.out.println("  - [" + f.rule() + "] " + f.detail());
            }
            if (granularity == Granularity.WHOLE_SET) {
                // The findings are per member because the export was parsed; the FIX is not.
                System.out.println("  note: this product has no per-object write, so correcting any"
                        + " of the above re-imports the whole entity set");
            }
            return 1;
        } catch (VendorException e) {
            System.out.println("[GATE] REFUSED:");
            System.out.println("  - [" + e.rule() + "] " + e.getMessage());
            return 2;
        } catch (Exception e) {
            System.err.println("[GATE] error: " + e.getMessage());
            return 2;
        }
    }
}
