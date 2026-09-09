package dev.krillin.bifrost.gates;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import dev.krillin.bifrost.core.conduit.ConduitException;
import dev.krillin.bifrost.core.conduit.ConduitPolicyWriter;
import dev.krillin.bifrost.core.conduit.ConduitProjection;
import dev.krillin.bifrost.core.schema.DefinitionStore;

/**
 * Emit the governed conduits as the {@code CommunicationPolicy} YAML Huginn reads.
 *
 * <p>{@code gates conduit-project <reg> --edge <address> --bind <ref>=<address> [--bind ...]
 * [--out <file>]} &mdash; 0 written / 2 usage or refusal.
 *
 * <p><b>This produces an artifact and enforces nothing</b>, the same posture as
 * {@link AclProjectGate}. What it adds over a YAML template is the registry: every bound ref must
 * actually be governed, because projecting governance for equipment nobody governs would produce a
 * confident policy whose every violation is meaningless.
 *
 * <p>The question the output lets Huginn answer is row 12's other half &mdash; <b>is there a write
 * path to governed equipment that is not the governed edge?</b> It needs no protocol overlap
 * between the two tools, and in fact the reverse: a Modbus write landing on a governed mixer, over
 * a protocol the edge does not even speak, is exactly the bypass.
 */
public final class ConduitProjectGate {

    private static final String USAGE = "Usage: gates conduit-project <reg> --edge <address>"
            + " --bind <ref>=<address> [--bind ...] [--out <file>]";

    public static void main(String[] args) {
        System.exit(run(args));
    }

    public static int run(String[] args) {
        String edge = null, out = null;
        List<String> binds = new ArrayList<>();
        List<String> pos = new ArrayList<>();
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--edge" -> edge = (++i < args.length) ? args[i] : null;
                case "--bind" -> {
                    if (++i < args.length) binds.add(args[i]);
                }
                case "--out" -> out = (++i < args.length) ? args[i] : null;
                default -> pos.add(args[i]);
            }
        }
        if (pos.isEmpty() || edge == null || binds.isEmpty()) {
            System.err.println(USAGE);
            if (binds.isEmpty() && !pos.isEmpty() && edge != null) {
                // Named separately: an empty policy is a plausible-looking thing to want, and it
                // governs nothing while looking like a successful projection.
                System.err.println("[GATE] at least one --bind is required;"
                        + " a projection with no equipment governs nothing");
            }
            return 2;
        }
        Path reg = Path.of(pos.get(0));
        try {
            Map<String, String> byAddress = new LinkedHashMap<>();
            List<ConduitProjection.GovernedEquipment> equipment = new ArrayList<>();
            DefinitionStore store = new DefinitionStore(reg);

            for (String bind : binds) {
                int eq = bind.indexOf('=');
                if (eq <= 0 || eq == bind.length() - 1) {
                    System.err.println("[GATE] error: --bind must be <ref>=<address>, got '" + bind + "'");
                    return 2;
                }
                String ref = bind.substring(0, eq);
                String address = bind.substring(eq + 1);

                // The check that makes this a Bifrost command. Everything else here is bookkeeping.
                if (store.latest(ref).isEmpty()) {
                    return refuse("conduit.equipment.ungoverned", "'" + ref
                            + "' is not in the governed registry at " + reg
                            + " - projecting governance for equipment nobody governs would make every"
                            + " violation it produces meaningless");
                }
                String clash = byAddress.putIfAbsent(address, ref);
                if (clash != null) {
                    return refuse("conduit.address.duplicate", "'" + ref + "' and '" + clash
                            + "' are both bound to " + address
                            + " - a violation there could not say which equipment was reached");
                }
                if (address.equals(edge)) {
                    return refuse("conduit.address.edge-is-equipment", "'" + ref + "' is bound to "
                            + address + ", which is also the edge - the edge's own traffic and every"
                            + " bypass would arrive at the same peer and could never be separated");
                }
                equipment.add(new ConduitProjection.GovernedEquipment(ref, address));
            }

            String yaml = new ConduitPolicyWriter()
                    .write(new ConduitProjection(edge, equipment), reg.toString());

            if (out != null) {
                Path f = Path.of(out);
                if (f.getParent() != null) Files.createDirectories(f.getParent());
                Files.writeString(f, yaml);
                System.out.println("[GATE] conduit-project -> " + out
                        + " (equipment=" + equipment.size() + ", edge=" + edge + ")");
            } else {
                System.out.println(yaml);
            }
            System.out.println("[GATE] the equipment-to-address binding is DECLARED, not discovered."
                    + " This is a FRAGMENT: it says who may write the governed equipment, not who may"
                    + " read it. Merge it into the site's CommunicationPolicy.");
            return 0;
        } catch (ConduitException e) {
            return refuse(e.rule(), e.getMessage().substring(e.rule().length() + 2));
        } catch (Exception e) {
            System.err.println("[GATE] error: " + e.getMessage());
            return 2;
        }
    }

    /** Refusals print to stdout in the house shape so a gate can grep them alongside the output. */
    private static int refuse(String rule, String detail) {
        System.out.println("[GATE] REFUSED:");
        System.out.println("  - [" + rule + "] " + detail);
        return 2;
    }
}
