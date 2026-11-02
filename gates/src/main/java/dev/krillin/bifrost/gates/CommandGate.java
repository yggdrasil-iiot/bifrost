package dev.krillin.bifrost.gates;

import com.fasterxml.jackson.databind.JsonNode;
import dev.krillin.bifrost.core.command.CommandProposal;
import java.nio.file.*;
import java.time.Clock;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;

/** File/JSON only gate over command proposals. It verifies and co-signs; delivering the approved envelope to an edge is
 *  not this command's job. */
public final class CommandGate {
    private CommandGate(){}
    static final String USAGE="usage: command verify <registry> <envelope> [--approved] | command approve <registry> <proposal> --approved-by <id> --approved-by-key <path> --policy <command-policy.json> --out <path>";
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
                default -> throw new IllegalArgumentException(USAGE);
            }
            MappingGate.emit(result);return 0;
        }catch(Exception e){
            try{MappingGate.emit(object().put("kind","command-refusal").put("accepted",false).put("error",String.valueOf(e.getMessage())).put("execution","excluded"));}catch(Exception ignored){}
            return e.getMessage()!=null&&e.getMessage().startsWith("usage")?2:1;
        }
    }
}
