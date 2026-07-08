package dev.krillin.bifrost.gates;

import java.util.Arrays;

/**
 * Single dispatcher entrypoint for the Bifrost CI gate CLIs.
 * Usage: gates &lt;schema|spec|policy|provenance&gt; &lt;args...&gt;
 */
public final class GatesCli {

    public static void main(String[] args) { System.exit(run(args)); }

    public static int run(String[] args) {
        if (args.length == 0) {
            System.err.println("Usage: gates <schema|spec|policy|provenance> <args...>");
            return 2;
        }
        String sub = args[0];
        String[] rest = Arrays.copyOfRange(args, 1, args.length);
        switch (sub) {
            case "schema":
                return SchemaGate.run(rest);
            case "spec":
                return SpecGate.run(rest);
            case "policy":
                return PolicyGate.run(rest);
            case "provenance":
                return ProvenancePublish.run(rest);
            default:
                System.err.println("unknown subcommand: " + sub);
                return 2;
        }
    }
}
