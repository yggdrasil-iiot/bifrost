package dev.krillin.bifrost.core.acl.opa;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.krillin.bifrost.core.acl.Decision;
import dev.krillin.bifrost.core.acl.Target;
import java.time.Instant;
import java.util.*;

/** The OPA half of the governed Method check: evaluates command_method.wasm in-process (Chicory) over facts the
 *  caller has already verified, after CommandAuthorizer has admitted the call. Fail-closed: an evaluation error,
 *  an empty result or any violation is a deny whose reason lists the violations, sorted. */
public final class OpaMethodAuthorizer {
    private static final ObjectMapper M = new ObjectMapper();
    private final OpaPolicy policy;

    public OpaMethodAuthorizer() { this.policy = OpaPolicy.fromResource("/opa/command_method.wasm"); }
    OpaMethodAuthorizer(OpaPolicy policy) { this.policy = policy; }   // test seam

    /** What the policy sees. Grants are the ActivationAction JSON names each principal holds on the stream;
     *  distinctKeys and headMatch are the caller's own verification results. */
    public record MethodFacts(String proposer, Collection<String> proposerGrants, String approver, Collection<String> approverGrants,
                              boolean distinctKeys, Instant notBefore, Instant notAfter, Instant now, boolean headMatch,
                              boolean evidenceUsable, Target target, String methodNodeId, String inputName, String inputType, double value) {}

    public Decision authorize(MethodFacts f) {
        try {
            ObjectNode input = M.createObjectNode();
            ObjectNode p = input.putObject("proposer");
            p.put("principal", f.proposer());
            f.proposerGrants().forEach(p.putArray("grants")::add);
            ObjectNode a = input.putObject("approver");
            a.put("principal", f.approver());
            f.approverGrants().forEach(a.putArray("grants")::add);
            input.put("distinctKeys", f.distinctKeys());
            input.putObject("window").put("notBefore", f.notBefore().getEpochSecond()).put("notAfter", f.notAfter().getEpochSecond());
            input.put("now", f.now().getEpochSecond());
            input.put("headMatch", f.headMatch());
            input.putObject("evidence").put("usable", f.evidenceUsable());
            input.putObject("target").put("group", f.target().group()).put("edge", f.target().edge()).put("device", f.target().device());
            input.put("method", f.methodNodeId());
            input.putArray("inputs").addObject().put("name", f.inputName()).put("type", f.inputType()).put("value", f.value());

            JsonNode dec = M.readTree(policy.eval(M.writeValueAsString(input))).path(0).path("result");
            if (dec.isMissingNode()) return Decision.deny("opa: empty result set (deny-by-default)");
            if (dec.path("allow").asBoolean(false)) return Decision.allow("command_method");
            List<String> v = new ArrayList<>();
            dec.path("violations").forEach(x -> v.add(x.asText()));
            Collections.sort(v);                                              // a set: no order from the module
            return Decision.deny("opa: " + (v.isEmpty() ? "deny" : String.join(",", v)));
        } catch (Exception e) {
            return Decision.deny("opa-eval-error: " + e.getMessage());       // fail-closed
        }
    }
}
