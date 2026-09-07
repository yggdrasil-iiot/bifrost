package dev.krillin.bifrost.core.schema;

import java.io.ByteArrayOutputStream;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Mints a recipe version reference. The ONLY place git runs in the whole feature — once, at publish.
 * Usage: RecipePublish <registryDir> <sourceRepoDir> <sourcePathRelToRepo> <ref> [<version>] [--kind <kind>]
 * Exit: 0 published (or no-op re-publish), 1 refused (dirty / no commit), 2 error/usage.
 */
public final class RecipePublish {

    private static final String USAGE = "Usage: RecipePublish <registryDir> <sourceRepoDir> <sourcePath> <ref> [<version>] [--kind <kind>]";
    private static final String DEFAULT_KIND = "recipe-setpoints";

    public static void main(String[] args) { System.exit(run(args)); }

    public static int run(String[] args) {
        // Scan out the position-independent --kind <value> flag, leaving only positionals behind.
        // --kind may appear at index 4 (no version) or index 5 (version given) — order-agnostic scan.
        String kind = DEFAULT_KIND;
        List<String> pos = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            if ("--kind".equals(args[i])) {
                if (i + 1 >= args.length) { System.err.println("[PUBLISH] error: --kind requires a value\n" + USAGE); return 2; }
                kind = args[++i];
            } else {
                pos.add(args[i]);
            }
        }
        if (pos.size() < 4) { System.err.println(USAGE); return 2; }
        Path registry = Path.of(pos.get(0));
        Path repo = Path.of(pos.get(1));
        String sourcePath = pos.get(2), ref = pos.get(3);
        String version = pos.size() > 4 ? pos.get(4) : "1.0.0";
        try {
            String status = gitText(repo, "status", "--porcelain", "--", sourcePath);
            if (status == null) { System.err.println("[PUBLISH] error: git status failed"); return 2; }
            if (!status.isBlank()) { System.err.println("[PUBLISH] refuse: '" + sourcePath + "' is dirty - commit first"); return 1; }
            String defRef = gitText(repo, "log", "-1", "--format=%H", "--", sourcePath);
            defRef = defRef == null ? null : defRef.trim();
            if (defRef == null || !defRef.matches("[0-9a-f]{40}")) { System.err.println("[PUBLISH] refuse: no commit for " + sourcePath); return 1; }
            byte[] blob = gitBytes(repo, "show", defRef + ":" + sourcePath);
            if (blob == null) { System.err.println("[PUBLISH] error: git show failed"); return 2; }
            String sha256 = sha256hex(blob);
            RecipeManifest m = new RecipeDefinitionStore(registry)
                    .publish(kind, ref, version, blob, defRef, sha256, sourcePath, System.currentTimeMillis());
            System.out.println("[PUBLISH] recipe " + ref + "/" + m.version() + " defRef=" + defRef + " sha256=" + sha256);
            return 0;
        } catch (Exception e) { System.err.println("[PUBLISH] error: " + e.getMessage()); return 2; }
    }

    private static String sha256hex(byte[] b) throws Exception {
        byte[] d = MessageDigest.getInstance("SHA-256").digest(b);
        StringBuilder s = new StringBuilder(); for (byte x : d) s.append(String.format("%02x", x)); return s.toString();
    }
    private static String gitText(Path dir, String... args) { byte[] o = gitBytes(dir, args); return o == null ? null : new String(o); }

    private static byte[] gitBytes(Path dir, String... args) {
        try {
            List<String> cmd = new ArrayList<>(List.of("git", "-C", dir.toString()));
            cmd.addAll(List.of(args));
            Process p = new ProcessBuilder(cmd).redirectErrorStream(false).start();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            Thread reader = new Thread(() -> { try { p.getInputStream().transferTo(out); } catch (Exception ignored) {} });
            reader.setDaemon(true); reader.start();
            if (!p.waitFor(15, TimeUnit.SECONDS)) { p.destroyForcibly(); return null; }
            reader.join();   // process already exited → stdout EOF guaranteed → unbounded join fully drains (no truncation)
            return p.exitValue() == 0 ? out.toByteArray() : null;
        } catch (Exception e) { return null; }
    }
}
