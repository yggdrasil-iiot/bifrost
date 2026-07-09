package dev.krillin.bifrost.core.conformance;
import java.util.*;
import dev.krillin.bifrost.core.schema.*;

/** Prescriptive model governance: a site UdtDefinition must CONFORM to an enterprise template.
 *  Subtyping/Liskov — the site may specialize (tighten ranges), extend (add members), but not violate.
 *  Per template member: structural (present), type, semanticId, range-envelope (site range ⊆ template range).
 *  Site members NOT in the template are allowed (extension). Violations accumulate. */
public final class TemplateConformanceChecker {

    public ConformanceVerdict check(UdtDefinition site, UdtDefinition template) {
        List<Violation> v = new ArrayList<>();
        Map<String, Member> siteMembers = new LinkedHashMap<>();
        for (Member m : site.members()) siteMembers.put(m.name(), m);

        for (Member t : template.members()) {
            Member s = siteMembers.get(t.name());
            if (s == null) {
                v.add(new Violation("template.member.missing",
                    "site '" + site.templateRef() + "' is missing required member '" + t.name()
                    + "' from template '" + template.templateRef() + "'"));
                continue;
            }
            if (!Objects.equals(t.type(), s.type())) v.add(new Violation("template.type.mismatch",
                "member '" + t.name() + "' type " + s.type() + " != template " + t.type()));
            if (!Objects.equals(t.semanticId(), s.semanticId())) v.add(new Violation("template.semanticId.mismatch",
                "member '" + t.name() + "' semanticId '" + s.semanticId() + "' != template '" + t.semanticId() + "'"));
            if (t.range() != null) {
                if (s.range() == null) {
                    v.add(new Violation("template.range.exceeds-envelope",
                        "member '" + t.name() + "' is unbounded but template envelope is [" + t.range().low() + "," + t.range().high() + "]"));
                } else {
                    if (s.range().low() < t.range().low()) v.add(new Violation("template.range.exceeds-envelope",
                        "member '" + t.name() + "' low " + s.range().low() + " < template low " + t.range().low()));
                    if (s.range().high() > t.range().high()) v.add(new Violation("template.range.exceeds-envelope",
                        "member '" + t.name() + "' high " + s.range().high() + " > template high " + t.range().high()));
                }
            }
        }
        return new ConformanceVerdict(v.isEmpty(), List.copyOf(v));
    }
}
