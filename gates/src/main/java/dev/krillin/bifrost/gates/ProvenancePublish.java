package dev.krillin.bifrost.gates;

import dev.krillin.bifrost.core.schema.RecipeDefinitionStore;
import dev.krillin.bifrost.core.schema.RecipePublish;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Optional;

/**
 * Provenance ③ CLI over the core recipe-publish/verify machinery. Two subcommands:
 *   publish &lt;registryDir&gt; &lt;sourceRepoDir&gt; &lt;sourcePath&gt; &lt;ref&gt; [&lt;version&gt;] [--kind &lt;kind&gt;]  — delegates to RecipePublish (mint); --kind flows through the raw pass-through.
 *   verify  &lt;registryDir&gt; &lt;ref&gt;                                                — recomputes sha256 over the
 *           materialized canonical bytes and compares to the manifest's self-attested contentSha256.
 * Exit: 0 = ok/verified, 1 = tamper detected (verify mismatch), 2 = error/usage.
 */
public final class ProvenancePublish {

    public static void main(String[] args) { System.exit(run(args)); }

    public static int run(String[] args) {
        if (args.length == 0) {
            System.err.println("Usage: provenance <publish|verify> ...");
            return 2;
        }
        String sub = args[0];
        String[] rest = Arrays.copyOfRange(args, 1, args.length);
        switch (sub) {
            case "publish":
                return RecipePublish.run(rest);
            case "verify":
                return verify(rest);
            default:
                System.err.println("Usage: provenance <publish|verify> ...");
                return 2;
        }
    }

    private static int verify(String[] args) {
        if (args.length < 2) {
            System.err.println("Usage: provenance verify <registryDir> <ref>");
            return 2;
        }
        Path registryDir = Path.of(args[0]);
        String ref = args[1];
        try {
            Optional<RecipeDefinitionStore.Resolved> resolvedOpt = new RecipeDefinitionStore(registryDir).latest(ref);
            if (resolvedOpt.isEmpty()) {
                System.err.println("[PROV-GATE] no such recipe: " + ref);
                return 2;
            }
            RecipeDefinitionStore.Resolved resolved = resolvedOpt.get();
            byte[] bytes = Files.readAllBytes(resolved.canonicalPath());
            String computed = sha256hex(bytes);
            String expected = resolved.manifest().contentSha256();
            String version = resolved.manifest().version();
            if (computed.equals(expected)) {
                System.out.println("[PROV-GATE] verify ref=" + ref + " version=" + version + " sha256=" + computed + " => OK");
                return 0;
            }
            System.out.println("[PROV-GATE] verify ref=" + ref + " version=" + version
                    + " sha256=" + computed + " manifest=" + expected + " => MISMATCH (tampered or unresolvable)");
            return 1;
        } catch (Exception e) {
            System.err.println("[PROV-GATE] error: " + e.getMessage());
            return 2;
        }
    }

    private static String sha256hex(byte[] b) throws Exception {
        byte[] d = MessageDigest.getInstance("SHA-256").digest(b);
        StringBuilder s = new StringBuilder();
        for (byte x : d) s.append(String.format("%02x", x));
        return s.toString();
    }
}
