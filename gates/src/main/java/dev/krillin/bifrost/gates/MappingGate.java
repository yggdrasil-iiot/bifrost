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
            if(a.length<2)throw new IllegalArgumentException("usage: mapping validate|diff|approve|publish|status|verify-attestation|sign-head|verify-head ...");
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
                    String usage="usage: mapping publish <registry> <bundle> <release-id> <version> --approval <id> [--by <id> --by-key <path> --approved-by <id> --approved-by-key <path> [--expires-in <ISO-8601 duration>]] [--anchor-store file|git --anchor-dir <dir>]";
                    require(a.length>=7&&a[5].equals("--approval"),usage);var o=options(a,7,usage);
                    result=registry(a[1],o).publish(Path.of(a[2]),a[3],a[4],a[6],signers(o,usage,false));
                }
                case "sign-head" -> {
                    String usage="usage: mapping sign-head <registry> <stream> --by <id> --by-key <path> --approved-by <id> --approved-by-key <path> [--expires-in <ISO-8601 duration>] [--anchor-store file|git --anchor-dir <dir>]";
                    require(a.length>=3,usage);var o=options(a,3,usage);result=registry(a[1],o).signHead(a[2],signers(o,usage,true));
                }
                case "verify-head" -> {
                    String usage="usage: mapping verify-head <registry> <stream> [--anchor-store file|git --anchor-dir <dir>]";
                    require(a.length>=3,usage);var o=options(a,3,usage);require(o.keySet().stream().allMatch(k->k.startsWith("--anchor")),usage);
                    result=registry(a[1],o).verifyHead(a[2]);
                }
                case "verify-attestation" -> {
                    require(a.length==5,"usage: mapping verify-attestation <registry> <release-id> <version> <release-sha256>");
                    result=new MappingRegistry(Path.of(a[1])).verifyAttestation(a[2],a[3],a[4]);
                }
                default -> throw new IllegalArgumentException("usage: unknown mapping command");
            }
            emit(result);return 0;
        }catch(Exception e){ObjectNodeBuilder.error(e);return e.getMessage()!=null&&e.getMessage().startsWith("usage")?2:1;}
    }
    private static final java.util.Set<String> OPTIONS=java.util.Set.of("--by","--by-key","--approved-by","--approved-by-key","--expires-in","--anchor-store","--anchor-dir");
    private static java.util.Map<String,String> options(String[] a,int from,String usage){
        java.util.Map<String,String> o=new java.util.HashMap<>();
        for(int i=from;i<a.length;i+=2)require(i+1<a.length&&OPTIONS.contains(a[i])&&o.put(a[i],a[i+1])==null,usage);
        return o;
    }
    /** The witness of head versions: registry/anchor/ by default, or a git repository kept off the box. */
    private static MappingRegistry registry(String path,java.util.Map<String,String> o){
        String kind=o.getOrDefault("--anchor-store","file"),dir=o.get("--anchor-dir");
        require(kind.equals("file")||kind.equals("git")&&dir!=null,"usage: --anchor-store file|git, git needs --anchor-dir");
        dev.krillin.bifrost.core.activation.AnchorStore anchors=kind.equals("git")?new dev.krillin.bifrost.core.identity.GitAnchorStore(Path.of(dir))
            :new dev.krillin.bifrost.core.activation.FileAnchorStore(dir==null?Path.of(path).toAbsolutePath().normalize():Path.of(dir));
        return new MappingRegistry(Path.of(path),java.time.Clock.systemUTC(),()->{},anchors);
    }
    private static MappingRegistry.HeadSigners signers(java.util.Map<String,String> o,String usage,boolean required){
        boolean any=o.containsKey("--by")||o.containsKey("--by-key")||o.containsKey("--approved-by")||o.containsKey("--approved-by-key")||o.containsKey("--expires-in");
        if(!any&&!required)return null;
        require(o.containsKey("--by")&&o.containsKey("--by-key")&&o.containsKey("--approved-by")&&o.containsKey("--approved-by-key"),usage);
        java.time.Duration life;
        try{life=o.containsKey("--expires-in")?java.time.Duration.parse(o.get("--expires-in")):MappingRegistry.DEFAULT_HEAD_LIFETIME;}catch(java.time.format.DateTimeParseException e){throw new IllegalArgumentException(usage);}
        return new MappingRegistry.HeadSigners(o.get("--by"),Path.of(o.get("--by-key")),o.get("--approved-by"),Path.of(o.get("--approved-by-key")),life);
    }
    static void emit(JsonNode doc) throws Exception {System.out.write(JSON.writeValueAsBytes(doc));System.out.write(10);System.out.flush();}
    private static final class ObjectNodeBuilder{
        static void error(Exception e){try{emit(object().put("kind","mapping-refusal").put("accepted",false).put("error",String.valueOf(e.getMessage())).put("execution","excluded"));}catch(Exception ignored){}}
    }
}
