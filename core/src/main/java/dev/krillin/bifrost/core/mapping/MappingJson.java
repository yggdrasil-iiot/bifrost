package dev.krillin.bifrost.core.mapping;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import com.networknt.schema.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/** Local wire parsing and bundled schemas only. Never resolves a caller-supplied schema URI. */
public final class MappingJson {
    private MappingJson() {}
    public static final ObjectMapper JSON = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
        .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private static final Map<String,JsonSchema> SCHEMAS=new ConcurrentHashMap<>();
    public static JsonNode read(Path p) throws Exception {
        if(Files.size(p)>4*1024*1024)throw new IllegalArgumentException("mapping.file-limit");
        return JSON.readTree(Files.readAllBytes(p));
    }
    public static ObjectNode object(){return JSON.createObjectNode();}
    public static String sha(byte[] b) throws Exception {return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    public static String sha(Path p) throws Exception {return sha(Files.readAllBytes(p));}
    public static byte[] bytes(JsonNode n) throws Exception {return JSON.writeValueAsBytes(sorted(n));}
    private static JsonNode sorted(JsonNode n) {
        if(n.isObject()){ObjectNode o=object();Set<String> keys=new TreeSet<>();n.fieldNames().forEachRemaining(keys::add);keys.forEach(k->o.set(k,sorted(n.get(k))));return o;}
        if(n.isArray()){ArrayNode a=JSON.createArrayNode();n.forEach(x->a.add(sorted(x)));return a;}
        return n;
    }
    public static void save(Path p,JsonNode n) throws Exception {Files.createDirectories(p.getParent());Files.write(p,bytes(n),StandardOpenOption.CREATE_NEW);}
    public static String text(JsonNode n,String k){return n.path(k).asText();}
    public static void require(boolean v,String code){if(!v)throw new IllegalArgumentException(code);}
    public static Path safe(Path root,String rel) throws Exception {
        require(rel.matches("[a-zA-Z0-9._/-]+")&&!rel.startsWith("/")&&!Arrays.asList(rel.split("/")).contains("..")&&!Arrays.asList(rel.split("/")).contains("."),"mapping.path");
        Path real=root.toRealPath(),p=root.resolve(rel).normalize();
        require(p.toRealPath().startsWith(real),"mapping.path");
        Path cursor=root;
        for(Path part:root.relativize(p)){cursor=cursor.resolve(part);require(!Files.isSymbolicLink(cursor),"mapping.symlink");}
        require(Files.isRegularFile(p),"mapping.file");return p;
    }
    private static JsonNode resource(String version,String file) throws Exception {
        require(version.matches("[0-9]+\\.[0-9]+\\.[0-9]+")&&file.matches("[a-z-]+\\.schema\\.json"),"mapping.schema-capability");
        try(var in=MappingJson.class.getResourceAsStream("/mapping-contracts/"+version+"/"+file)){
            require(in!=null,"mapping.schema-capability");return JSON.readTree(in);
        }
    }
    private static JsonNode expand(JsonNode n,String version,String file,JsonNode root,int depth) throws Exception {
        require(depth<80,"mapping.schema-depth");
        if(n.isObject()&&n.has("$ref")){
            String ref=n.get("$ref").asText();String[] parts=ref.split("#",2);String name=parts[0].isEmpty()?file:parts[0],targetVersion=version;
            if(name.startsWith("../")){
                String[] cross=name.split("/");require(cross.length==3&&cross[0].equals(".."),"mapping.schema-capability");
                targetVersion=cross[1];name=cross[2];
            }
            JsonNode doc=parts[0].isEmpty()?root:resource(targetVersion,name);
            JsonNode value=parts.length==1||parts[1].isEmpty()?doc:doc.at(parts[1]);
            require(!value.isMissingNode(),"mapping.schema-reference");return expand(value,targetVersion,name,doc,depth+1);
        }
        if(n.isObject()){
            ObjectNode o=object();var fields=n.fields();
            while(fields.hasNext()){var f=fields.next();if(!Set.of("$id","$defs").contains(f.getKey()))o.set(f.getKey(),expand(f.getValue(),version,file,root,depth+1));}
            return o;
        }
        if(n.isArray()){ArrayNode a=JSON.createArrayNode();for(JsonNode x:n)a.add(expand(x,version,file,root,depth+1));return a;}
        return n;
    }
    private static JsonNode logicalSchema(JsonNode n,String version,int depth) throws Exception {
        require(depth<80,"mapping.schema-depth");
        if(n.isObject()&&n.has("$ref")){
            String ref=text(n,"$ref");if(ref.startsWith("#"))return n;
            String[] parts=ref.split("#",2);JsonNode doc=resource(version,parts[0]);
            JsonNode value=parts.length==1?doc:doc.at(parts[1]);require(!value.isMissingNode(),"mapping.schema-reference");
            return logicalSchema(value,version,depth+1);
        }
        if(n.isObject()){ObjectNode o=object();var fields=n.fields();while(fields.hasNext()){var f=fields.next();if(!f.getKey().equals("$id"))o.set(f.getKey(),logicalSchema(f.getValue(),version,depth+1));}return o;}
        if(n.isArray()){ArrayNode a=JSON.createArrayNode();for(JsonNode x:n)a.add(logicalSchema(x,version,depth+1));return a;}
        return n;
    }
    public static void schema(JsonNode doc,String kind) throws Exception {
        String version=text(doc,"schemaVersion"),key=version+"/"+kind;
        if(version.equals("2.12.0")&&kind.equals("semantic-definition"))LogicalStructure.preflight(doc);
        JsonSchema schema=SCHEMAS.get(key);
        if(schema==null){
            JsonNode raw=resource(version,kind+".schema.json");
            SchemaValidatorsConfig config=new SchemaValidatorsConfig();config.setFormatAssertionsEnabled(true);
            schema=JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012).getSchema(version.equals("2.12.0")?logicalSchema(raw,version,0):expand(raw,version,kind+".schema.json",raw,0),config);
            SCHEMAS.put(key,schema);
        }
        require(schema.validate(doc).isEmpty(),"mapping.schema:"+key);
    }
    public static String manifestDigest(Map<String,String> files) throws Exception {
        StringBuilder s=new StringBuilder();new TreeMap<>(files).forEach((p,h)->s.append(p).append("\t").append(h).append("\n"));
        return sha(s.toString().getBytes(StandardCharsets.UTF_8));
    }
}
