package dev.krillin.bifrost.core.acl.opa;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import dev.krillin.bifrost.core.acl.CommandRequest;
import dev.krillin.bifrost.core.acl.Decision;

/** OPA/Rego command authorizer: evaluates command_authz.wasm in-process (Chicory). Context-aware —
 *  the go-forward richer engine alongside the hand-rolled CommandAuthorizer. Fail-closed. */
public final class OpaCommandAuthorizer {
    private static final ObjectMapper M = new ObjectMapper();
    private final OpaPolicy policy;

    public OpaCommandAuthorizer() { this.policy = OpaPolicy.fromResource("/opa/command_authz.wasm"); }
    OpaCommandAuthorizer(OpaPolicy policy) { this.policy = policy; }   // test seam

    public Decision authorize(CommandRequest req, Context ctx) {
        try {
            ObjectNode input = M.createObjectNode();
            input.put("command", req.command());
            ObjectNode t = input.putObject("target");
            t.put("group", req.target().group());
            t.put("edge", req.target().edge());
            t.put("device", req.target().device());
            input.put("type", req.type());
            input.set("value", M.valueToTree(req.value()));
            ObjectNode c = input.putObject("context");
            c.put("state", ctx.state());
            c.put("hour", ctx.hour());

            String resultJson = policy.eval(M.writeValueAsString(input));      // [{"result": {...}}]
            JsonNode dec = M.readTree(resultJson).path(0).path("result");
            if (dec.isMissingNode()) return Decision.deny("opa: empty result set (deny-by-default)");
            boolean allow = dec.path("allow").asBoolean(false);
            return allow ? Decision.allow(dec.path("rule").asText("opa"))
                         : Decision.deny(dec.path("reason").asText("opa-deny"));
        } catch (Exception e) {
            return Decision.deny("opa-eval-error: " + e.getMessage());       // fail-closed
        }
    }
}
