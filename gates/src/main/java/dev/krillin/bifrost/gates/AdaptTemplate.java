package dev.krillin.bifrost.gates;
import java.nio.file.Path;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.krillin.bifrost.core.schema.*;
import dev.krillin.bifrost.core.conformance.adapter.*;

/** Adapts a FOREIGN external-standard template file to the canonical UdtDefinition JSON.
 *  Usage: AdaptTemplate &lt;ignition|cfihos|aas&gt; &lt;extFile&gt; &lt;outFile&gt; &lt;ref&gt; &lt;version&gt;. Exit 0 ok / 2 error. */
public final class AdaptTemplate {
    public static void main(String[] args) { System.exit(run(args)); }

    public static int run(String[] args) {
        if (args.length < 5) { System.err.println("Usage: AdaptTemplate <ignition|cfihos|aas> <extFile> <outFile> <ref> <version>"); return 2; }
        String kind = args[0];
        try {
            TemplateAdapter adapter = switch (kind) {
                case "ignition" -> new IgnitionUdtAdapter();
                case "cfihos"   -> new CfihosTemplateAdapter();
                case "aas"      -> new AasSubmodelAdapter();
                default -> null;
            };
            if (adapter == null) { System.err.println("[GATE] error: unknown adapter kind '" + kind + "' (expected ignition|cfihos|aas)"); return 2; }
            ObjectMapper mapper = JsonMapperFactory.create();
            JsonNode tree = mapper.readTree(Path.of(args[1]).toFile());
            UdtDefinition def = adapter.adapt(tree, args[3], args[4]);
            mapper.writerWithDefaultPrettyPrinter().writeValue(Path.of(args[2]).toFile(), def);
            System.out.println("[GATE] adapted " + kind + " -> " + args[2] + " (ref=" + args[3] + "@" + args[4] + ", members=" + def.members().size() + ")");
            return 0;
        } catch (Exception e) { System.err.println("[GATE] error: " + e.getMessage()); return 2; }
    }
}
