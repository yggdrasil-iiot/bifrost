package yggdrasil.bifrost.heimdall;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Date;

import org.eclipse.tahu.message.SparkplugBPayloadEncoder;
import org.eclipse.tahu.message.model.MetricDataType;
import org.eclipse.tahu.message.model.SparkplugBPayload;
import org.eclipse.tahu.message.model.SparkplugBPayload.SparkplugBPayloadBuilder;
import org.eclipse.tahu.message.model.Metric.MetricBuilder;

/**
 * Heimdall's own Sparkplug B edge node (stage A): the command edge, never the data edge Muninn owns.
 *
 * <p>It births with NBIRTH ({@code seq} 0, {@code bdSeq}, {@code Node Control/Rebirth} and the one
 * declared String metric {@code bifrost/command/v1}) and leaves an NDEATH Will carrying the same
 * {@code bdSeq}. It models no devices: a host such as UMH reads a device id as a location, so a
 * Heimdall device would be a phantom asset. Correlated answers stay on {@code bifrost/<group>/RESULT}.
 *
 * <p>{@code bdSeq} advances on every MQTT CONNECT, including after a process restart, wraps 255 to
 * 0, and is kept on a rebirth without CONNECT (Sparkplug 3.0). Sparkplug prescribes no storage, so
 * it lives in a small file under the command ledger's durable directory, written and synced BEFORE
 * the CONNECT that carries it: a crash between the two can skip a number, never reuse one. A reused
 * number would let a delayed Will from the killed process declare the restarted node dead.
 * Muninn's {@code EdgeSession} keeps bdSeq in memory and is deliberately not the template.
 */
final class CommandNode {

    static final String REBIRTH = "Node Control/Rebirth";

    private final String group;
    private final String edge;
    private final Path file;
    private final SparkplugBPayloadEncoder encoder = new SparkplugBPayloadEncoder();
    private int bdSeq = -1;

    CommandNode(String group, String edge, Path ledgerDir) {
        this.group = group;
        this.edge = edge;
        this.file = ledgerDir.resolve("sparkplug").resolve(fold(group) + "__" + fold(edge) + ".bdseq");
    }

    String birthTopic() {
        return "spBv1.0/" + group + "/NBIRTH/" + edge;
    }

    String deathTopic() {
        return "spBv1.0/" + group + "/NDEATH/" + edge;
    }

    Path file() {
        return file;
    }

    /** The bdSeq of the current (or last) CONNECT; -1 before the first {@link #advance}. */
    synchronized int bdSeq() {
        return bdSeq;
    }

    /**
     * Read the last bdSeq, compute the next, write and sync it, and return it for the CONNECT about
     * to happen. An absent file starts at 0; an unreadable or corrupt one refuses (the caller must
     * not CONNECT), because guessing could reuse a number a broker still holds in a Will.
     */
    synchronized int advance() throws IOException {
        int next;
        if (Files.exists(file)) {
            String text = Files.readString(file, StandardCharsets.UTF_8).strip();
            int last;
            try {
                last = Integer.parseInt(text);
            } catch (NumberFormatException e) {
                throw new IOException("command.node.bdseq: " + file + " is corrupt (" + text + ")");
            }
            if (last < 0 || last > 255) {
                throw new IOException("command.node.bdseq: " + file + " is out of range (" + last + ")");
            }
            next = (last + 1) % 256;
        } else {
            next = 0;
        }
        write(next);
        bdSeq = next;
        return next;
    }

    private void write(int value) throws IOException {
        Path dir = file.getParent();
        Files.createDirectories(dir);
        Path tmp = dir.resolve(file.getFileName() + ".tmp");
        try (FileChannel ch = FileChannel.open(tmp, StandardOpenOption.CREATE, StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING)) {
            ch.write(ByteBuffer.wrap((value + "\n").getBytes(StandardCharsets.UTF_8)));
            ch.force(true);
        }
        try {
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
        }
        syncDirectory(dir);
    }

    /**
     * Sync the directory entry so the rename survives a power loss. POSIX file systems allow it;
     * Windows cannot open a directory as a channel, and NTFS journals the rename itself, so there the
     * attempt is skipped rather than turned into a refusal.
     */
    private static void syncDirectory(Path dir) throws IOException {
        if (System.getProperty("os.name", "").toLowerCase().startsWith("windows")) {
            return;
        }
        try (FileChannel ch = FileChannel.open(dir, StandardOpenOption.READ)) {
            ch.force(true);
        }
    }

    /** NBIRTH for the current bdSeq: seq 0, on CONNECT and on every rebirth. */
    synchronized byte[] birth() throws Exception {
        SparkplugBPayload p = new SparkplugBPayloadBuilder()
                .setTimestamp(new Date())
                .setSeq(0L)
                .addMetric(new MetricBuilder("bdSeq", MetricDataType.Int64, (long) bdSeq).createMetric())
                .addMetric(new MetricBuilder(REBIRTH, MetricDataType.Boolean, false).createMetric())
                .addMetric(new MetricBuilder(NcmdOpcUaBridge.METHOD_METRIC, MetricDataType.String, "").createMetric())
                .createPayload();
        return encoder.getBytes(p, false);
    }

    /** The NDEATH a Will carries (and an orderly stop publishes): the bdSeq only, no seq. */
    synchronized byte[] death() throws Exception {
        SparkplugBPayload p = new SparkplugBPayloadBuilder()
                .setTimestamp(new Date())
                .addMetric(new MetricBuilder("bdSeq", MetricDataType.Int64, (long) bdSeq).createMetric())
                .createPayload();
        return encoder.getBytes(p, false);
    }

    private static String fold(String s) {
        return s.replaceAll("[^A-Za-z0-9._-]", "-");
    }
}
