package dev.krillin.bifrost.heimdall;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.eclipse.tahu.message.SparkplugBPayloadDecoder;
import org.eclipse.tahu.message.model.Metric;
import org.eclipse.tahu.message.model.MetricDataType;
import org.eclipse.tahu.message.model.SparkplugBPayload;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class CommandNodeTest {

    private static final String GROUP = "Bifrost:Line1";
    private static final String EDGE = "recipe-edge-cmd";

    @Test void topics_are_the_command_edge_nbirth_and_ndeath(@TempDir Path ledger) {
        CommandNode n = new CommandNode(GROUP, EDGE, ledger);
        assertEquals("spBv1.0/Bifrost:Line1/NBIRTH/recipe-edge-cmd", n.birthTopic());
        assertEquals("spBv1.0/Bifrost:Line1/NDEATH/recipe-edge-cmd", n.deathTopic());
        assertEquals(ledger.resolve("sparkplug").resolve("Bifrost-Line1__recipe-edge-cmd.bdseq"), n.file());
    }

    @Test void bdseq_starts_at_zero_advances_and_survives_a_new_instance(@TempDir Path ledger) throws Exception {
        CommandNode n = new CommandNode(GROUP, EDGE, ledger);
        assertEquals(-1, n.bdSeq());
        assertEquals(0, n.advance());
        assertEquals(1, n.advance());
        // A restart is a new instance over the same file: it must continue, never restart at 0.
        CommandNode restarted = new CommandNode(GROUP, EDGE, ledger);
        assertEquals(2, restarted.advance());
        assertEquals("2", Files.readString(n.file(), StandardCharsets.UTF_8).strip());
    }

    @Test void bdseq_wraps_from_255_to_0(@TempDir Path ledger) throws Exception {
        CommandNode n = new CommandNode(GROUP, EDGE, ledger);
        Files.createDirectories(n.file().getParent());
        Files.writeString(n.file(), "255\n");
        assertEquals(0, n.advance());
    }

    @Test void a_corrupt_or_out_of_range_bdseq_refuses(@TempDir Path ledger) throws Exception {
        CommandNode n = new CommandNode(GROUP, EDGE, ledger);
        Files.createDirectories(n.file().getParent());
        Files.writeString(n.file(), "seven\n");
        IOException e = assertThrows(IOException.class, n::advance);
        assertTrue(e.getMessage().startsWith("command.node.bdseq"), e.getMessage());
        Files.writeString(n.file(), "256\n");
        assertThrows(IOException.class, n::advance);
        assertEquals("256", Files.readString(n.file()).strip(), "a refusal writes nothing");
    }

    @Test void two_edges_keep_two_counters(@TempDir Path ledger) throws Exception {
        CommandNode a = new CommandNode(GROUP, EDGE, ledger);
        CommandNode b = new CommandNode(GROUP, "other-cmd", ledger);
        a.advance();
        a.advance();
        assertEquals(0, b.advance());
    }

    @Test void birth_declares_bdseq_rebirth_and_the_method_metric_only(@TempDir Path ledger) throws Exception {
        CommandNode n = new CommandNode(GROUP, EDGE, ledger);
        n.advance();
        n.advance();
        SparkplugBPayload p = new SparkplugBPayloadDecoder().buildFromByteArray(n.birth(), null);
        assertEquals(0L, p.getSeq());
        assertEquals(3, p.getMetrics().size(), String.valueOf(p.getMetrics()));
        assertEquals(1L, ((Number) find(p, "bdSeq").getValue()).longValue());
        assertEquals(MetricDataType.Int64, find(p, "bdSeq").getDataType());
        assertEquals(MetricDataType.Boolean, find(p, CommandNode.REBIRTH).getDataType());
        assertEquals(MetricDataType.String, find(p, NcmdOpcUaBridge.METHOD_METRIC).getDataType());
    }

    @Test void death_carries_the_same_bdseq_and_nothing_else(@TempDir Path ledger) throws Exception {
        CommandNode n = new CommandNode(GROUP, EDGE, ledger);
        n.advance();
        n.advance();
        n.advance();
        SparkplugBPayload p = new SparkplugBPayloadDecoder().buildFromByteArray(n.death(), null);
        assertEquals(1, p.getMetrics().size());
        assertEquals(2L, ((Number) find(p, "bdSeq").getValue()).longValue());
    }

    private static Metric find(SparkplugBPayload p, String name) {
        for (Metric m : p.getMetrics()) {
            if (name.equals(m.getName())) {
                return m;
            }
        }
        fail("no metric " + name + " in " + p.getMetrics());
        return null;
    }
}
