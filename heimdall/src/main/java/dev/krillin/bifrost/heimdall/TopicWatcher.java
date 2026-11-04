package dev.krillin.bifrost.heimdall;

import java.nio.charset.StandardCharsets;

import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.MqttCallback;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;
import org.eclipse.tahu.message.SparkplugBPayloadDecoder;
import org.eclipse.tahu.message.model.Metric;
import org.eclipse.tahu.message.model.SparkplugBPayload;

/**
 * Gate support: subscribe to one topic and print what arrives, one line per message. The
 * counterpart to {@link RogueNcmd}, which publishes.
 *
 * <p>The gates previously had no way to observe a topic at all — every script could publish and
 * none could subscribe — which is why the retained status topic and the RESULT response detail were
 * both unassertable from a gate.
 *
 * <pre>
 *   java -cp bifrost-heimdall.jar dev.krillin.bifrost.heimdall.TopicWatcher &lt;topic&gt; [seconds]
 *   java -cp bifrost-heimdall.jar dev.krillin.bifrost.heimdall.TopicWatcher --sparkplug &lt;topic&gt; [seconds]
 *   java -cp bifrost-heimdall.jar dev.krillin.bifrost.heimdall.TopicWatcher --clear &lt;topic&gt;
 * </pre>
 *
 * <p>{@code --sparkplug} decodes each payload as Sparkplug B and prints one line per message,
 * {@code [WATCH] <topic> retained=<b> seq=<n> metrics=[<name>:<type>=<value>, ...]} (seq is
 * {@code -} when absent, as in an NDEATH), so a gate can assert an NBIRTH's metrics and an NDEATH's
 * bdSeq; the topic may carry MQTT wildcards.
 *
 * <p>{@code --clear} publishes a zero-length retained message, which is how MQTT deletes a retained
 * value. The resilience gate needs it because a retained "offline" left by a PREVIOUS run would
 * otherwise satisfy this run's assertion that the will fired — the gate would stay green with the
 * will removed.
 */
public final class TopicWatcher {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.err.println("usage: TopicWatcher [--sparkplug] <topic> [seconds] | TopicWatcher --clear <topic>");
            System.exit(2);
        }
        String broker = System.getenv().getOrDefault("MQTT_URL", "tcp://localhost:1883");
        boolean clear = "--clear".equals(args[0]);
        boolean sparkplug = "--sparkplug".equals(args[0]);
        int at = (clear || sparkplug) ? 1 : 0;
        String topic = args[at];
        long seconds = (!clear && args.length > at + 1) ? Long.parseLong(args[at + 1]) : 60L;

        MqttClient c = new MqttClient(broker, "topic-watcher-" + System.nanoTime(), new MemoryPersistence());
        MqttConnectOptions opts = new MqttConnectOptions();
        opts.setCleanSession(true);
        c.connect(opts);

        if (clear) {
            // Zero-length + retained is the MQTT way to delete a retained value for a topic.
            MqttMessage empty = new MqttMessage(new byte[0]);
            empty.setRetained(true);
            empty.setQos(1);
            c.publish(topic, empty);
            System.out.println("[WATCH] cleared retained " + topic);
            System.out.flush();
            c.disconnect();
            c.close();
            return;
        }

        c.setCallback(new MqttCallback() {
            @Override public void connectionLost(Throwable cause) {
                System.out.println("[WATCH] connection lost: " + cause);
                System.out.flush();
            }

            @Override public void deliveryComplete(IMqttDeliveryToken token) {
                // nothing to do: this watcher only subscribes
            }

            @Override public void messageArrived(String t, MqttMessage m) {
                // Flushed every line: the gate greps this file while the process is still running.
                System.out.println(sparkplug ? sparkplugLine(t, m)
                        : "[WATCH] " + t + " = " + new String(m.getPayload(), StandardCharsets.UTF_8));
                System.out.flush();
            }
        });
        c.subscribe(topic, 1);
        System.out.println("[WATCH] subscribed " + topic);
        System.out.flush();

        Thread.sleep(seconds * 1000L);
        c.disconnect();
        c.close();
    }

    static String sparkplugLine(String topic, MqttMessage m) {
        try {
            SparkplugBPayload p = new SparkplugBPayloadDecoder().buildFromByteArray(m.getPayload(), null);
            java.util.List<String> metrics = new java.util.ArrayList<>();
            for (Metric metric : p.getMetrics()) {
                metrics.add(metric.getName() + ":" + metric.getDataType() + "=" + metric.getValue());
            }
            return "[WATCH] " + topic + " retained=" + m.isRetained() + " seq="
                    + (p.getSeq() == null ? "-" : p.getSeq()) + " metrics=" + metrics;
        } catch (Exception e) {
            return "[WATCH] " + topic + " retained=" + m.isRetained() + " undecodable (" + m.getPayload().length
                    + " bytes): " + e;
        }
    }

    private TopicWatcher() {
    }
}
