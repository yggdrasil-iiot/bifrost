package dev.krillin.bifrost.gates;

import com.fasterxml.jackson.databind.JsonNode;
import dev.krillin.bifrost.core.command.CommandProposal;
import java.nio.file.*;
import java.time.Clock;
import java.util.Base64;
import java.util.Date;
import org.eclipse.paho.client.mqttv3.MqttClient;
import org.eclipse.paho.client.mqttv3.persist.MemoryPersistence;
import org.eclipse.tahu.message.SparkplugBPayloadEncoder;
import org.eclipse.tahu.message.model.Metric.MetricBuilder;
import org.eclipse.tahu.message.model.MetricDataType;
import org.eclipse.tahu.message.model.PropertyDataType;
import org.eclipse.tahu.message.model.PropertySet.PropertySetBuilder;
import org.eclipse.tahu.message.model.PropertyValue;
import org.eclipse.tahu.message.model.SparkplugBPayload.SparkplugBPayloadBuilder;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;

/** Gate over command proposals: verify and approve are file/JSON only; publish delivers an envelope to the edge its
 *  statement names, as the one String metric of a Sparkplug B NCMD. Publish checks nothing - the edge does - so a gate
 *  can also deliver an envelope the edge must refuse. */
public final class CommandGate {
    private CommandGate(){}
    static final String USAGE="usage: command verify <registry> <envelope> [--approved] | command approve <registry> <proposal> --approved-by <id> --approved-by-key <path> --policy <command-policy.json> --out <path> | command publish <envelope> --broker <url>";
    /** Must match the edge's NcmdOpcUaBridge.METHOD_METRIC; gates does not depend on heimdall. */
    static final String METRIC="bifrost/command/v1";
    public static int run(String[] a){return run(a,Clock.systemUTC());}
    static int run(String[] a,Clock clock){
        try{
            require(a.length>=3,USAGE);
            JsonNode result;
            switch(a[0]){
                case "verify" -> {
                    require(a.length==3||a.length==4&&a[3].equals("--approved"),USAGE);
                    result=CommandProposal.verify(Path.of(a[1]),read(Path.of(a[2])),a.length==4,clock);
                }
                case "approve" -> {
                    require(a.length==11&&a[3].equals("--approved-by")&&a[5].equals("--approved-by-key")&&a[7].equals("--policy")&&a[9].equals("--out"),USAGE);
                    Path out=Path.of(a[10]);
                    require(!Files.exists(out),"command.out-exists");
                    var approval=CommandProposal.approve(Path.of(a[1]),read(Path.of(a[2])),a[4],Path.of(a[6]),Path.of(a[8]),clock);
                    if(out.toAbsolutePath().getParent()!=null)Files.createDirectories(out.toAbsolutePath().getParent());
                    Files.write(out,JSON.writeValueAsBytes(approval.envelope()),StandardOpenOption.CREATE_NEW);
                    result=approval.report().put("out",out.toString());
                }
                case "publish" -> {
                    require(a.length==4&&a[2].equals("--broker"),USAGE);
                    result=publish(Files.readAllBytes(Path.of(a[1])),a[3]);
                }
                default -> throw new IllegalArgumentException(USAGE);
            }
            MappingGate.emit(result);return 0;
        }catch(Exception e){
            if(a.length>0&&a[0].equals("publish")&&!(e instanceof IllegalArgumentException))e.printStackTrace();
            try{MappingGate.emit(object().put("kind","command-refusal").put("accepted",false).put("error",String.valueOf(e.getMessage())).put("execution","excluded"));}catch(Exception ignored){}
            return e.getMessage()!=null&&e.getMessage().startsWith("usage")?2:1;
        }
    }

    /** One NCMD to spBv1.0/<group>/NCMD/<edge> of the statement's target: the envelope bytes as the String metric, property
     *  op=method, payload uuid = cmdId so the edge's NDATA answer correlates. */
    static JsonNode publish(byte[] envelope,String broker) throws Exception {
        var p=CommandProposal.parse(Base64.getDecoder().decode(text(JSON.readTree(envelope),"payload")));
        String topic="spBv1.0/"+p.target().group()+"/NCMD/"+p.target().edge();
        var props=new PropertySetBuilder().addProperty("op",new PropertyValue(PropertyDataType.String,"method")).createPropertySet();
        var payload=new SparkplugBPayloadBuilder().setUuid(p.cmdId()).setTimestamp(new Date())
            .addMetric(new MetricBuilder(METRIC,MetricDataType.String,new String(envelope,java.nio.charset.StandardCharsets.UTF_8)).properties(props).createMetric())
            .createPayload();
        MqttClient client=new MqttClient(broker,("gates-command-"+p.cmdId()).substring(0,36),new MemoryPersistence());
        client.connect();
        try{client.publish(topic,new SparkplugBPayloadEncoder().getBytes(payload,false),1,false);}
        finally{client.disconnect();client.close();}
        return object().put("kind","command-publication").put("accepted",true).put("cmdId",p.cmdId()).put("topic",topic).put("metric",METRIC);
    }
}
