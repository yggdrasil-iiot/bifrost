package dev.krillin.bifrost.heimdall;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.util.Date;
import java.util.UUID;

import dev.krillin.bifrost.core.acl.CommandEnvelope;
import dev.krillin.bifrost.core.identity.Ed25519Keys;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;
import org.eclipse.tahu.message.SparkplugBPayloadEncoder;
import org.eclipse.tahu.message.model.Metric.MetricBuilder;
import org.eclipse.tahu.message.model.MetricDataType;
import org.eclipse.tahu.message.model.PropertyDataType;
import org.eclipse.tahu.message.model.PropertySet;
import org.eclipse.tahu.message.model.PropertySet.PropertySetBuilder;
import org.eclipse.tahu.message.model.PropertyValue;
import org.eclipse.tahu.message.model.SparkplugBPayload;
import org.eclipse.tahu.message.model.SparkplugBPayload.SparkplugBPayloadBuilder;

/**
 * Rogue NCMD publisher — bypasses any legitimate upstream writer entirely and publishes a
 * single-command-metric Sparkplug NCMD straight to the broker, to prove the bridge's edge
 * authorization (deny-by-default + range) denies commands no authorized writer ever issued. Used
 * by the runtime NCMD gate's T3 (deny-by-default node) and T4 (defense-in-depth: an allowed node
 * but out-of-range value).
 *
 * <p>Wire contract: one metric whose {@code name} = the OPC-UA nodeId, {@code value}/
 * {@code dataType} the setpoint, plus a payload uuid and an {@code op=write} String property on
 * the metric; published to {@code spBv1.0/<group>/NCMD/<edge>}.
 *
 * <p>args: {@code {nodeId, value, dataType}} — only {@code Double} is needed for the gate.
 * Run: {@code mvn -q compile exec:java -Dexec.mainClass=dev.krillin.bifrost.heimdall.RogueNcmd
 * -Dexec.args="ns=2;s=Recipe/Secret 1.0 Double"}
 *
 * <p><b>R1 signing.</b> Optional trailing {@code --sign <principal> <pkcs8-b64-file>} adds the
 * {@code sub}/{@code sig} metric properties the edge verifies when {@code REQUIRE_SIGNED_COMMAND}
 * is on. Optional {@code --cmd-id <id>} pins the payload uuid, which the replay leg of the command
 * identity gate needs in order to send the same signed payload twice.
 *
 * <p>Extended rather than copied on purpose: every gate already publishes through this class, and a
 * second publisher differing by two properties is a pair that drifts.
 */
public final class RogueNcmd {

    public static void main(String[] args) throws Exception {
        String nodeId = args[0];
        String dataType = args.length > 2 && !args[2].startsWith("--") ? args[2] : "Double";
        MetricDataType mdt = "Double".equals(dataType) ? MetricDataType.Double : MetricDataType.String;
        Object value = "Double".equals(dataType) ? Double.parseDouble(args[1]) : args[1];

        String signAs = optArg(args, "--sign", 0);
        String keyFile = optArg(args, "--sign", 1);
        String pinnedCmdId = optArg(args, "--cmd-id", 0);

        String broker = env("MQTT_URL", "tcp://localhost:1883");
        String group = env("SPB_GROUP", "Bifrost:Line1");
        String edge = env("SPB_EDGE", "recipe-edge");
        String topic = "spBv1.0/" + group + "/NCMD/" + edge;
        String uuid = pinnedCmdId != null ? pinnedCmdId : UUID.randomUUID().toString();

        PropertySetBuilder pb = new PropertySetBuilder()
                .addProperty("op", new PropertyValue(PropertyDataType.String, "write"));
        if (signAs != null && keyFile != null) {
            // Signed over the TYPED value, through the same CommandEnvelope the edge verifies with.
            // Formatting the value here instead would reintroduce exactly the divergence
            // CommandEnvelope.canonicalValue exists to remove.
            PrivateKey key = Ed25519Keys.privateKey(
                    Files.readString(Path.of(keyFile), StandardCharsets.UTF_8).trim());
            String sig = CommandEnvelope.sign(group, edge, uuid, nodeId, value, dataType, key);
            pb.addProperty("sub", new PropertyValue(PropertyDataType.String, signAs))
              .addProperty("sig", new PropertyValue(PropertyDataType.String, sig));
            System.out.println("[ROGUE] signed as " + signAs + " cmdId=" + uuid);
        }
        PropertySet props = pb.createPropertySet();
        SparkplugBPayload payload = new SparkplugBPayloadBuilder()
                .setUuid(uuid)
                .setTimestamp(new Date())
                .addMetric(new MetricBuilder(nodeId, mdt, value).properties(props).createMetric())
                .createPayload();
        byte[] bytes = new SparkplugBPayloadEncoder().getBytes(payload, false);

        MqttClient client = new MqttClient(broker, "rogue-" + uuid, new MemoryPersistence());
        client.connect();
        client.publish(topic, bytes, 1, false);
        client.disconnect();
        client.close();
        System.out.println("[ROGUE] published NCMD topic=" + topic + " cmd=" + nodeId
                + " val=" + value + " type=" + dataType + " uuid=" + uuid);
    }

    /** The {@code n}-th value after {@code flag}, or null when the flag is absent. */
    private static String optArg(String[] args, String flag, int n) {
        for (int i = 0; i < args.length; i++) {
            if (flag.equals(args[i]) && i + 1 + n < args.length) {
                return args[i + 1 + n];
            }
        }
        return null;
    }

    private static String env(String key, String dflt) {
        String v = System.getenv(key);
        return v != null && !v.isBlank() ? v : dflt;
    }

    private RogueNcmd() {}
}
