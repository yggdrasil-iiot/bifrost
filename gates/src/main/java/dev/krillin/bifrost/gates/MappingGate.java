package dev.krillin.bifrost.gates;

import dev.krillin.bifrost.core.mapping.*;
import java.nio.file.*;
import com.fasterxml.jackson.databind.JsonNode;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;

/** File/JSON only mapping contract gate. Approval keys are operator CLI inputs, never a Tyr API field. */
public final class MappingGate {
    private MappingGate(){}
    public static int run(String[] a){
        try{
            if(a.length<2)throw new IllegalArgumentException("usage: mapping validate|diff|approve|publish|status ...");
            JsonNode result;
            switch(a[0]){
                case "validate" -> {require(a.length==2,"usage");var c=new MappingBundle().validate(Path.of(a[1]));emit(c.report());return c.accepted()?0:1;}
                case "diff" -> {require(a.length==3,"usage");result=MappingRegistry.diff(Path.of(a[1]),Path.of(a[2]));}
                case "recover" -> {require(a.length==2,"usage: mapping recover <registry>");result=new MappingRegistry(Path.of(a[1])).recover();}
                case "gc" -> {require(a.length==3||a.length==5&&a[3].equals("--quarantine"),"usage: mapping gc <registry> <grace-seconds> [--quarantine <plan-sha256>]");result=new MappingRegistry(Path.of(a[1])).gc(Long.parseLong(a[2]),a.length==5?a[4]:null);}
                case "lifecycle" -> {require(a.length==2,"usage: mapping lifecycle <registry>");result=new MappingRegistry(Path.of(a[1])).lifecycle();}
                case "catalog" -> {require(a.length==2,"usage: mapping catalog <registry>");result=new MappingRegistry(Path.of(a[1])).catalog();}
                case "status" -> {require(a.length==3,"usage");result=new MappingRegistry(Path.of(a[1])).status(a[2]);}
                case "approve" -> {
                    require(a.length==12&&a[4].equals("--by")&&a[6].equals("--by-key")&&a[8].equals("--approved-by")&&a[10].equals("--approved-by-key"),"usage: mapping approve <registry> <bundle> <approval-id> --by <id> --by-key <path> --approved-by <id> --approved-by-key <path>");
                    result=new MappingRegistry(Path.of(a[1])).approve(Path.of(a[2]),a[3],a[5],Path.of(a[7]),a[9],Path.of(a[11]));
                }
                case "publish" -> {
                    require(a.length==7&&a[5].equals("--approval"),"usage: mapping publish <registry> <bundle> <release-id> <version> --approval <id>");
                    result=new MappingRegistry(Path.of(a[1])).publish(Path.of(a[2]),a[3],a[4],a[6]);
                }
                default -> throw new IllegalArgumentException("usage: unknown mapping command");
            }
            emit(result);return 0;
        }catch(Exception e){ObjectNodeBuilder.error(e);return e.getMessage()!=null&&e.getMessage().startsWith("usage")?2:1;}
    }
    static void emit(JsonNode doc) throws Exception {System.out.write(JSON.writeValueAsBytes(doc));System.out.write(10);System.out.flush();}
    private static final class ObjectNodeBuilder{
        static void error(Exception e){try{emit(object().put("kind","mapping-refusal").put("accepted",false).put("error",String.valueOf(e.getMessage())).put("execution","excluded"));}catch(Exception ignored){}}
    }
}
