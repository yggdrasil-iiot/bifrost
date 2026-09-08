package dev.krillin.bifrost.heimdall;

import java.nio.charset.StandardCharsets;

import org.eclipse.paho.client.mqttv3.IMqttDeliveryToken;
import org.eclipse.paho.client.mqttv3.MqttCallback;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;

/**
 * Gate support: subscribe to one topic and print what arrives, one line per message. The
 * counterpart to {@link RogueNcmd}, which publishes.
 *
 * <p>The gates previously had no way to observe a topic at all — every script could publish and
 * none could subscribe — which is why the retained status topic and the NDATA response detail were
 * both unassertable from a gate.
 *
 * <pre>
 *   java -cp bifrost-heimdall.jar dev.krillin.bifrost.heimdall.TopicWatcher &lt;topic&gt; [seconds]
 *   java -cp bifrost-heimdall.jar dev.krillin.bifrost.heimdall.TopicWatcher --clear &lt;topic&gt;
 * </pre>
 *
 * <p>{@code --clear} publishes a zero-length retained message, which is how MQTT deletes a retained
 * value. The resilience gate needs it because a retained "offline" left by a PREVIOUS run would
 * otherwise satisfy this run's assertion that the will fired — the gate would stay green with the
 * will removed.
 */
public final class TopicWatcher {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            System.err.println("usage: TopicWatcher <topic> [seconds] | TopicWatcher --clear <topic>");
            System.exit(2);
        }
        String broker = System.getenv().getOrDefault("MQTT_URL", "tcp://localhost:1883");
        boolean clear = "--clear".equals(args[0]);
        String topic = clear ? args[1] : args[0];
        long seconds = (!clear && args.length > 1) ? Long.parseLong(args[1]) : 60L;

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
                System.out.println("[WATCH] " + t + " = " + new String(m.getPayload(), StandardCharsets.UTF_8));
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

    private TopicWatcher() {
    }
}
