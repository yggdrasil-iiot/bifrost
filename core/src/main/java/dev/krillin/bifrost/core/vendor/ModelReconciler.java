package dev.krillin.bifrost.core.vendor;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import dev.krillin.bifrost.core.schema.Member;
import dev.krillin.bifrost.core.schema.UdtDefinition;
import dev.krillin.bifrost.core.schema.Violation;

/**
 * Diffs a governed {@link UdtDefinition} against a vendor's copy of it, once that copy has been
 * normalized through the inbound {@code TemplateAdapter}.
 *
 * <p>Comparing two CANONICAL definitions rather than a definition against a foreign tree is what
 * keeps this vendor-ignorant: the anti-corruption layer that already exists for the inbound
 * direction does the whole job, and nothing here knows Ignition or Kepware exists.
 *
 * <p><b>Members only, and deliberately.</b> {@code TemplateAdapter.adapt(external, ref, version)}
 * takes the identity as parameters because the external document does not carry Bifrost's, so a
 * templateRef or version comparison would check an operator's argument against itself and could
 * never fire. Which governed definition to compare against is therefore an operator input, and this
 * answers "does this vendor object agree with this definition" -- not "is every governed definition
 * present in the vendor", which needs an inventory the export does not carry.
 *
 * <p>Every divergence is reported, not the first: an operator fixing one per round trip is a worse
 * outcome than a list, and a member wrong in two ways produces two findings for the same reason.
 */
public final class ModelReconciler {

    public ReconciliationVerdict reconcile(UdtDefinition governed, UdtDefinition vendor,
                                           Granularity remediationUnit) {
        List<Violation> findings = new ArrayList<>();
        Map<String, Member> vendorByName = byName(vendor);
        Map<String, Member> governedByName = byName(governed);

        for (Member g : governed.members()) {
            Member v = vendorByName.get(g.name());
            if (v == null) {
                findings.add(new Violation("vendor.member.missing",
                        "the governed definition declares '" + g.name() + "' and the vendor's copy"
                        + " does not have it"));
                continue;
            }
            compareMember(g, v, findings);
        }
        for (Member v : vendor.members()) {
            if (!governedByName.containsKey(v.name())) {
                findings.add(new Violation("vendor.member.unexpected",
                        "the vendor's copy has '" + v.name() + "' and the governed definition does"
                        + " not declare it"));
            }
        }
        return new ReconciliationVerdict(findings.isEmpty(), remediationUnit, findings);
    }

    /** All three attributes are checked; a member wrong in two ways yields two findings. */
    private static void compareMember(Member governed, Member vendor, List<Violation> findings) {
        if (!Objects.equals(governed.type(), vendor.type())) {
            findings.add(new Violation("vendor.member.type-mismatch",
                    "'" + governed.name() + "' is " + governed.type() + " in the governed definition"
                    + " and " + vendor.type() + " in the vendor's copy"));
        }
        if (!Objects.equals(governed.range(), vendor.range())) {
            findings.add(new Violation("vendor.member.range-mismatch",
                    "'" + governed.name() + "' has range " + show(governed.range())
                    + " in the governed definition and " + show(vendor.range()) + " in the vendor's copy"));
        }
        if (!Objects.equals(governed.semanticId(), vendor.semanticId())) {
            findings.add(new Violation("vendor.member.semantic-id-mismatch",
                    "'" + governed.name() + "' points at " + show(governed.semanticId())
                    + " in the governed definition and " + show(vendor.semanticId())
                    + " in the vendor's copy"));
        }
    }

    /** Member order is a serialization accident, so both sides are indexed by name. */
    private static Map<String, Member> byName(UdtDefinition d) {
        Map<String, Member> m = new LinkedHashMap<>();
        for (Member x : d.members()) m.putIfAbsent(x.name(), x);
        return m;
    }

    private static String show(Object v) {
        return v == null ? "none" : v.toString();
    }
}
