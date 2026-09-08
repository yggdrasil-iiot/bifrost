package dev.krillin.bifrost.core.activation;
import java.time.Clock;
import java.util.*;
import dev.krillin.bifrost.core.schema.Violation;

/** Governs the activation act: only resolvable+content-sealed bytes, four-eyes SoD, guarded rollback.
 *  Fail-closed — any check fails ⇒ refuse, ledger untouched. */
public final class ActivationService {
    private final ArtifactResolver resolver;
    private final ActivationLedger ledger;
    private final Clock clock;
    public ActivationService(ArtifactResolver resolver, ActivationLedger ledger, Clock clock) {
        this.resolver = resolver; this.ledger = ledger; this.clock = clock;
    }

    public ActivationVerdict activate(ActivationRequest r) { return activate(r, null, null); }

    public ActivationVerdict activate(ActivationRequest r, LedgerSigner signer, ActivationPolicy policy) {
        boolean breakGlass = false;
        try {
            var resolved = resolver.resolve(r.kind(), r.ref(), r.version());
            if (resolved.isEmpty()) return refuse("activation.artifact.unresolved",
                    r.kind() + " " + r.ref() + "@" + r.version() + " is not a resolvable governed artifact");
            if (r.approvedBy() == null || r.approvedBy().isBlank())
                return refuse("activation.approval.missing", "activation requires a distinct approver (--approved-by)");
            if (r.approvedBy().equals(r.by()))
                return refuse("activation.approval.self", "approver '" + r.by() + "' must differ from the activator (four-eyes)");
            if (r.rollback() && !versionInHistory(r))
                return refuse("activation.rollback.unknown-version",
                        "cannot rollback to " + r.version() + " - never activated on target " + r.target());
            if (signer != null) {                                   // T5: fail-closed identity checks
                var idv = signer.preflight();
                if (!idv.isEmpty()) return new ActivationVerdict(false, null, idv);
                // Bind the signing identity to the event's NAMED principals, so the record's integrity holds
                // at the point of record — not only when a later verifier rejects a signed-but-unverifiable line.
                if (!signer.activatorPrincipal().equals(r.by()) || !signer.approverPrincipal().equals(r.approvedBy()))
                    return refuse("identity.signer.principal-mismatch",
                            "signing keys (" + signer.activatorPrincipal() + "/" + signer.approverPrincipal()
                            + ") must match the named activator/approver (" + r.by() + "/" + r.approvedBy() + ")");
                // T6 authZ (deny-by-default) — only on the signed path (authZ presupposes authN).
                ActivationPolicy p = (policy != null) ? policy : ActivationPolicy.denyAll();
                ActivationAuthorizer authz = new ActivationAuthorizer();
                AuthzDecision act = authz.authorize(p, r.by(), ActivationAction.ACTIVATE, r.target(), r.kind(), r.ref());
                if (!act.allowed())
                    return refuse("activation.authz.denied", "activator '" + r.by() + "' not permitted to ACTIVATE "
                            + r.target() + "/" + r.kind() + "/" + r.ref() + " [" + act.reason() + "]");
                AuthzDecision app = authz.authorize(p, r.approvedBy(), ActivationAction.APPROVE, r.target(), r.kind(), r.ref());
                if (!app.allowed()) {
                    // The emergency path, DERIVED from policy and never claimed by the caller. A duty
                    // principal is granted BREAK_GLASS_APPROVE and not APPROVE, so the one person
                    // holding a duty key cannot write an unmarked activation - which is the failure
                    // this exists to prevent, and a request flag could not have prevented it.
                    //
                    // APPROVE is tried FIRST, so an ordinary approver's path is unchanged.
                    AuthzDecision bg = authz.authorize(p, r.approvedBy(),
                            ActivationAction.BREAK_GLASS_APPROVE, r.target(), r.kind(), r.ref());
                    if (!bg.allowed())
                        return refuse("activation.authz.denied", "approver '" + r.approvedBy() + "' not permitted to APPROVE "
                                + r.target() + "/" + r.kind() + "/" + r.ref() + " [" + app.reason() + "]");
                    breakGlass = true;
                    // Loud, in the one place the control plane looks. No alerting transport is
                    // claimed here, and none exists.
                    System.err.println("[GATE] BREAK-GLASS approver=" + r.approvedBy()
                            + " activator=" + r.by() + " target=" + r.target() + "/" + r.kind() + "/" + r.ref());
                }
            }
            String prior = ledger.active(r.target(), r.kind(), r.ref()).map(ActivationEvent::version).orElse(null);
            ActivationEvent e = new ActivationEvent(r.target(), r.kind(), r.ref(), r.version(),
                    resolved.get().sha256(), r.by(), r.approvedBy(), clock.millis(), prior,
                    breakGlass ? "BREAK_GLASS" : (r.rollback() ? "ROLLBACK" : "ACTIVATE"));
            ledger.append(e, signer);
            return new ActivationVerdict(true, e, List.of());
        } catch (Exception ex) {
            return refuse("activation.error", ex.getMessage());
        }
    }

    private boolean versionInHistory(ActivationRequest r) throws Exception {
        for (LedgerEntry en : ledger.history(r.target())) {
            ActivationEvent e = en.event();
            if (e.kind().equals(r.kind()) && e.ref().equals(r.ref()) && e.version().equals(r.version())) return true;
        }
        return false;
    }
    private static ActivationVerdict refuse(String rule, String detail) {
        return new ActivationVerdict(false, null, List.of(new Violation(rule, detail)));
    }
}
