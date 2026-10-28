package dev.krillin.bifrost.core.mapping;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import java.nio.file.*;
import java.math.BigDecimal;
import java.util.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;

/** Independent Bifrost receiver. Consumes wire data, never imports or invokes Tyr implementation. */
public final class MappingBundle {
    public static final String CAPABILITY="bifrost-mapping-v1";
    public record Checked(ObjectNode report,JsonNode proposal,JsonNode submission,Map<String,JsonNode> documents,Map<String,String> files) {
        public boolean accepted(){return report.path("accepted").asBoolean();}
    }
    private final List<ObjectNode> findings=new ArrayList<>();
    private final Map<String,JsonNode> docs=new LinkedHashMap<>();
    private final Map<String,String> files=new TreeMap<>();
    private final Map<String,Sig> graphSigs=new HashMap<>();
    private Path root;
    private record Sig(String type,JsonNode unit,Set<String> sources,String stage,JsonNode array) {}
    private void add(String code,String path){ObjectNode f=object();f.put("ruleCode",code);f.put("path",path);f.put("detail",code);findings.add(f);}
    private void check(boolean ok,String code,String path){if(!ok)add(code,path);}
    private static String key(String k,String id,String ver){return k+":"+id+"@"+ver;}
    private static String key(JsonNode d){return key(text(d,"kind"),text(d,"id"),text(d,"version"));}
    private JsonNode resolve(String kind,JsonNode ref,String path){
        JsonNode d=docs.get(key(kind,text(ref,"id"),text(ref,"version")));
        if(d==null)add("reference.missing",path);return d;
    }
    private void pin(String path,String hash) throws Exception {
        require(!files.containsKey(path),"bundle.duplicate-path");
        require(sha(safe(root,path)).equals(hash),"bundle.digest:"+path);files.put(path,hash);
    }
    public Checked validate(Path folder) {
        root=folder;JsonNode p=null,s=null;
        try{
            p=read(safe(root,"proposal.json"));schema(p,"mapping-proposal");
            require(Set.of("2.0.0","2.6.0","2.7.0","2.18.0","2.19.0","2.20.0","2.21.0","2.22.0").contains(text(p,"schemaVersion")),"capability.proposal-version");
            files.put("proposal.json",sha(root.resolve("proposal.json")));
            s=read(safe(root,"submission.json"));schema(s,"mapping-submission");
            require(text(s,"proposalSha256").equals(files.get("proposal.json")),"submission.proposal-digest");
            JsonNode base=s.get("baseRelease");
            require(base.equals(p.path("baseRelease")),"submission.base-reference");
            files.put("submission.json",sha(root.resolve("submission.json")));
            for(JsonNode e:p.path("files")){
                String path=text(e,"path");pin(path,text(e,"sha256"));JsonNode d=read(root.resolve(path));
                require(text(d,"kind").equals(text(e,"kind"))&&text(d,"id").equals(text(e,"id"))&&text(d,"version").equals(text(e,"version")),"bundle.identity");
                require(Set.of("source-definition","semantic-definition","target-instance","value-graph","mapping-set","write-definition","evidence-artifact","source-observation","import-batch","semantic-lifecycle","mapping-template","template-application","record-mapping").contains(text(d,"kind")),"capability.document-kind");
                schema(d,text(d,"kind"));require(docs.putIfAbsent(key(d),d)==null,"bundle.duplicate-id");
            }
            for(JsonNode d:docs.values())if(text(d,"kind").equals("evidence-artifact")){
                String path=text(d.path("file"),"path"),hash=text(d.path("file"),"sha256");
                if(files.containsKey(path))require(files.get(path).equals(hash),"evidence.digest");else pin(path,hash);
            }
            long total=0;for(String path:files.keySet())total+=Files.size(safe(root,path));
            require(total<=32L*1024*1024&&files.size()<=4096,"bundle.limit");
            try(var walk=Files.walk(root)){
                for(Path f:walk.filter(Files::isRegularFile).toList()){
                    String rel=root.relativize(f).toString().replace('\\','/');
                    require(files.containsKey(rel),"bundle.unlisted-file:"+rel);
                }
            }
            require(docs.values().stream().anyMatch(d->Set.of("mapping-set","record-mapping").contains(text(d,"kind")))||Set.of("2.18.0","2.19.0","2.20.0","2.21.0","2.22.0").contains(text(p,"schemaVersion"))&&docs.values().stream().anyMatch(d->text(d,"kind").equals("semantic-lifecycle")),"mapping.required");
            for(JsonNode d:docs.values()){
                String path=key(d);evidence(d.path("evidenceRefs"),path);
                switch(text(d,"kind")){
                    case "source-definition" -> source(d);
                    case "semantic-definition" -> semantic(d);
                    case "import-batch" -> {
                        // Retain raw provenance. No template/alias re-interpretation is delegated to Tyr.
                        try{
                            if(text(d,"schemaVersion").equals("2.14.0")){
                                if(!MappingImportWorkflow.validate(d,docs))add("import.unresolved",path);
                            }else{
                                if(d.has("fileIssue"))add("import.unresolved",path);
                                for(JsonNode o:d.path("observations"))if(!o.path("issues").isEmpty()||o.path("draft").isNull())add("import.unresolved",path);
                            }
                            for(JsonNode q:d.path("reviews"))if(text(q,"decision").equals("resolve-source")){
                                ObjectNode reviewed=q.path("source").deepCopy();reviewed.put("status","ready");source(reviewed);evidence(reviewed.path("evidenceRefs"),path);
                            }
                        }catch(Exception ex){add(ex.getMessage()==null?"import.workflow-invalid":ex.getMessage(),path);}
                        JsonNode art=docs.values().stream().filter(x->text(x,"kind").equals("evidence-artifact")&&text(x,"id").equals("import-"+text(d,"id"))).findFirst().orElse(null);
                        check(art!=null,"import.evidence-mismatch",path);
                        if(art!=null)check(Arrays.equals(Base64.getDecoder().decode(text(d,"bytesBase64")),Files.readAllBytes(safe(root,text(art.path("file"),"path"))))&&text(d,"sha256").equals(text(art.path("file"),"sha256")),"import.evidence-mismatch",path);
                    }
                }
            }
            JsonNode context=s.path("context");
            Map<String,JsonNode> connections=new HashMap<>();Set<String> equipment=new HashSet<>();
            for(JsonNode e:context.path("equipment"))check(equipment.add(text(e,"id")),"context.duplicate-equipment","submission");
            for(JsonNode connection:context.path("connections")){check(connections.putIfAbsent(text(connection,"id"),connection)==null,"context.duplicate-connection","submission");check(equipment.contains(text(connection,"equipmentInstanceId")),"context.equipment","submission");}
            for(JsonNode d:docs.values())if(d.has("equipmentInstanceId")){
                check(equipment.contains(text(d,"equipmentInstanceId")),"context.equipment",key(d));
                if(text(d,"kind").equals("source-definition")&&!d.path("connectionProfileRef").isNull()){
                    JsonNode connection=connections.get(text(d,"connectionProfileRef"));
                    check(connection!=null&&text(connection,"equipmentInstanceId").equals(text(d,"equipmentInstanceId"))&&text(connection,"accessProfileRef").equals(text(d,"accessProfileRef")),"context.connection",key(d));
                }
            }
            if(docs.values().stream().anyMatch(d->MappingTemplates.KINDS.contains(text(d,"kind"))))MappingTemplates.validate(docs.values(),List.of());
            if(docs.values().stream().anyMatch(d->text(d,"kind").equals("record-mapping")))RecordMappings.validate(docs.values(),List.of(),this::validateDerived);
            if(docs.values().stream().anyMatch(d->text(d,"schemaVersion").equals("2.22.0")))require(text(p,"schemaVersion").equals("2.22.0"),"broadcast.envelope");
            if(docs.values().stream().anyMatch(d->text(d,"schemaVersion").equals("2.21.0"))){require(Set.of("2.21.0","2.22.0").contains(text(p,"schemaVersion")),"record-field.envelope");RecordFields.validate(docs.values());}
            concepts();
            if(docs.values().stream().anyMatch(d->text(d,"kind").equals("semantic-lifecycle")))SemanticLifecycle.validate(governanceDocuments(docs.values()),List.of(),Map.of());
            for(JsonNode g:GraphDependencies.order(docs.values()))graph(g);
            mappings();writes();
        }catch(Exception ex){add(ex.getMessage()==null?"bundle.invalid":ex.getMessage(),"bundle");}
        ObjectNode report=object();report.put("kind","mapping-validation");report.put("schemaVersion","2.9.0");
        if(files.containsKey("proposal.json"))report.put("proposalSha256",files.get("proposal.json"));else report.putNull("proposalSha256");
        try{report.put("bundleSha256",manifestDigest(files));}catch(Exception ex){report.putNull("bundleSha256");}
        report.put("accepted",findings.isEmpty());report.set("findings",JSON.valueToTree(findings));report.put("capability",CAPABILITY);report.put("execution","excluded");
        return new Checked(report,p,s,Map.copyOf(docs),Map.copyOf(files));
    }
    static List<JsonNode> governanceDocuments(Collection<JsonNode> docs) throws Exception {List<JsonNode> out=new ArrayList<>(docs);out.addAll(RecordMappings.governance(docs));return out;}
    private void validateDerived(List<JsonNode> derived) throws Exception {
        MappingBundle scoped=new MappingBundle();scoped.root=root;for(JsonNode d:docs.values())if(text(d,"kind").equals("evidence-artifact"))scoped.docs.put(key(d),d);
        for(JsonNode d:derived){schema(d,text(d,"kind"));scoped.docs.put(key(d),d);scoped.evidence(d.path("evidenceRefs"),key(d));}
        for(JsonNode d:derived){if(text(d,"kind").equals("source-definition"))scoped.source(d);if(text(d,"kind").equals("semantic-definition"))scoped.semantic(d);}
        scoped.concepts();for(JsonNode g:GraphDependencies.order(scoped.docs.values()))scoped.graph(g);scoped.mappings();require(scoped.findings.isEmpty(),"record.derived-invalid:"+scoped.findings);
    }
    private void evidence(JsonNode refs,String path) {
        for(JsonNode r:refs)try{
            var arts=docs.values().stream().filter(x->text(x,"kind").equals("evidence-artifact")&&text(x,"id").equals(text(r,"artifactId"))).toList();
            require(arts.size()==1,"evidence.missing");Path p=safe(root,text(arts.get(0).path("file"),"path"));JsonNode l=r.path("locator");
            switch(text(l,"kind")){
                case "text-line" -> require(l.path("line").asInt()<=Files.readAllLines(p).size(),"evidence.locator");
                case "json-pointer" -> require(!read(p).at(text(l,"pointer")).isMissingNode(),"evidence.locator");
                case "xlsx-cell" -> require(XlsxEvidence.hasCell(p,text(l,"sheet"),text(l,"cell")),"evidence.locator");
                default -> add("capability.evidence-locator",path);
            }
        }catch(Exception e){add("evidence.locator",path);}
    }
    private static final Set<String> NUM=Set.of("Int16","UInt16","Int32","UInt32","Int64","Float32","Float64","Double","Decimal");
    private static final Map<String,Integer> WIDTH=Map.of("Int16",2,"UInt16",2,"Int32",4,"UInt32",4,"Int64",8,"Float32",4,"Float64",8,"Boolean",1);
    private void source(JsonNode s) {
        String path=key(s),profile=text(s,"accessProfileRef"),kind=text(s.path("access"),"kind"),type=text(s.path("rawRepresentation"),"valueType");
        JsonNode a=s.path("access"),r=s.path("rawRepresentation");String stage=text(s,"inputStage");
        check(text(s,"status").equals("ready"),"source.not-ready",path);if(!s.path("viewOf").isNull())view(s);
        Map<String,String> profiles=Map.of("ab-logix-symbol-v1","symbol","s7-1500-opcua-v1","opcua-node","s7-300-db-v1","db-offset","melsec-device-v1","device-register","constant-v1","constant","solution-tag-v1","solution-tag","external-value-v1","external-value");
        check(kind.equals(profiles.get(profile)),"source.profile-mismatch",path);
        boolean bytes=Set.of("db-offset","device-register").contains(kind);
        check(text(r,"mode").equals(bytes?"bytes":"typed"),"source.representation",path);
        for(var it=a.fields();it.hasNext();){var f=it.next();if(Set.of("symbol","opcua-node","db-offset","device-register").contains(kind)&&!f.getKey().equals("bitOffset"))check(!f.getValue().isNull(),"source.incomplete",path);}
        if(bytes)check(!r.path("byteOrder").isNull()&&!r.path("wordOrder").isNull(),"source.incomplete",path);
        if(kind.equals("device-register"))check(!s.path("addressRadix").isNull(),"source.incomplete",path);
        if(kind.equals("opcua-node")){
            String ident=text(a,"identifierType");JsonNode v=a.path("identifier");
            check(ident.equals("numeric")?v.isIntegralNumber()&&v.asLong()>=0&&v.asLong()<=4294967295L:v.isTextual(),"source.node-identifier",path);
            if(ident.equals("guid"))try{UUID.fromString(v.asText());}catch(Exception e){add("source.node-identifier",path);}
        }
        if(kind.equals("external-value")){
            boolean none=text(a,"expressionLanguage").equals("none");
            check(none?a.path("expression").isNull():a.path("expression").isTextual()&&!a.path("expression").asText().isBlank(),"source.expression-mode",path);
        }
        if(kind.equals("constant"))try{
            JsonNode v=a.path("value");
            if(type.equals("Boolean"))require(v.isBoolean(),"constant.boolean");
            else if(type.equals("String"))require(v.isTextual()&&v.asText().length()<=4096,"constant.string");
            else{
                require(v.isTextual()&&v.asText().length()<=256&&v.asText().matches("[+-]?(?:[0-9]+(?:\\.[0-9]*)?|\\.[0-9]+)(?:[eE][+-]?[0-9]{1,4})?"),"constant.numeric");
                BigDecimal n=new BigDecimal(v.asText());require(Math.abs(n.scale())<=1000,"constant.numeric");
                if(type.equals("Int32"))require(n.stripTrailingZeros().scale()<=0&&n.compareTo(BigDecimal.valueOf(Integer.MIN_VALUE))>=0&&n.compareTo(BigDecimal.valueOf(Integer.MAX_VALUE))<=0,"constant.range");
                if(type.equals("Double"))require(n.abs().compareTo(new BigDecimal("1.7976931348623157e308"))<=0,"constant.range");
            }
        }catch(Exception e){add("constant.invalid",path);}
        if(Set.of("constant","external-value","solution-tag").contains(kind))check(!text(s.path("unit"),"status").equals("unknown"),"source.unit-unconfirmed",path);
        int width=WIDTH.getOrDefault(type,0);
        if(r.has("codec")){
            JsonNode codec=r.get("codec");String c=text(codec,"kind");
            width=switch(c){case "ascii-fixed" -> codec.path("length").asInt();case "bcd16" -> 2;case "s7-date-time" -> 8;default -> 0;};
            check(stage.equals("raw")&&!a.hasNonNull("bitOffset")&&!r.has("bitCoordinate"),"source.codec-stage",path);
            if(Set.of("ascii-fixed","s7-date-time").contains(c))check(text(r,"byteOrder").equals("big")&&text(r,"wordOrder").equals("high-first"),"source.codec-wire-order",path);
            if(c.equals("s7-date-time"))check(kind.equals("db-offset")&&!codec.path("timezone").isNull(),"source.timezone-required",path);
        }
        if(a.hasNonNull("bitOffset")){
            if(!Set.of("1.0.0","1.1.0").contains(text(s,"schemaVersion")))check(r.has("bitCoordinate"),"source.bit-coordinate-required",path);
            if(text(r.path("bitCoordinate"),"kind").equals("native-byte"))check(a.path("bitOffset").asInt()<=7&&r.path("bitCoordinate").path("byteIndex").asInt()<width,"source.bit-coordinate",path);
        }else check(!r.has("bitCoordinate"),"source.bit-coordinate-unused",path);
        if(kind.equals("device-register")&&text(a,"addressUnit").equals("bit")){
            check(type.equals("Boolean")&&!r.has("codec")&&!r.has("bitCoordinate"),"source.native-bit-representation",path);width=1;
        }
        if(kind.equals("device-register")){
            boolean bit=text(a,"addressUnit").equals("bit");
            Set<String> bitAreas=Set.of("M","X","Y","L","S","B");
            Set<String> wordAreas=Set.of("D","W","R","ZR","SD","TN","CN");
            if(!Set.of("1.0.0","1.1.0").contains(text(s,"schemaVersion")))check((bit?bitAreas:wordAreas).contains(text(a,"deviceArea")),"source.area-unsupported",path);
        }
        if(s.has("fixedArray"))array(s,null,path);
        else if(bytes&&width>0){int actual=kind.equals("device-register")?(text(a,"addressUnit").equals("bit")?1:a.path("wordCount").asInt()*2):a.path("byteLength").asInt();check(width==actual,"source.width",path);}
    }
    private void semantic(JsonNode d) {
        List<JsonNode> definitions;
        try{definitions=LogicalStructure.layout(d).definitions();}catch(IllegalArgumentException e){add(e.getMessage(),key(d));return;}
        Set<String> mids=new HashSet<>();for(JsonNode m:definitions){
            if(LogicalStructure.container(m))continue;
            check(!text(m.path("unit"),"status").equals("unknown"),"semantic.unit",key(d));
            if(!m.path("range").isNull())try{check(new BigDecimal(text(m.get("range"),"low")).compareTo(new BigDecimal(text(m.get("range"),"high")))<=0,"semantic.range",key(d));}catch(Exception e){add("semantic.range",key(d));}
        }
    }
    private void concepts(){
        Map<String,JsonNode> seen=new HashMap<>();for(JsonNode d:docs.values())if(text(d,"kind").equals("semantic-definition")){
            List<JsonNode> definitions;try{definitions=LogicalStructure.layout(d).definitions();}catch(IllegalArgumentException e){continue;}
            for(JsonNode m:definitions){
            JsonNode sig=LogicalStructure.signature(m);
            JsonNode prior=seen.putIfAbsent(text(m,"semanticId"),sig);check(prior==null||prior.equals(sig),"semantic.identity-conflict",key(d));
        }}
    }
    private void array(JsonNode s,JsonNode indices,String path){
        try{
            JsonNode f=s.path("fixedArray"),a=s.path("access"),r=s.path("rawRepresentation");
            int rank=f.path("shape").size(),count=1;require(rank>=1&&rank<=3&&f.path("lowerBounds").size()==rank&&f.path("strides").size()==rank,"array.rank");
            int width=WIDTH.getOrDefault(text(r,"valueType"),0);require(width>0&&!r.has("codec")&&!r.has("bitCoordinate")&&!a.hasNonNull("bitOffset"),"array.element-unsupported");
            boolean typed=text(r,"mode").equals("typed"),word=text(a,"kind").equals("device-register");
            String unit=typed?"element":word?"word16":"byte";require(text(f,"strideUnit").equals(unit)&&(!word||text(a,"addressUnit").equals("word16")),"array.stride-unit");
            long base=typed?0:word?a.path("addressIndex").asLong():a.path("byteOffset").asLong();
            long start=f.path("range").path("start").asLong(),end=f.path("range").path("endExclusive").asLong();
            int extent=typed?1:word?width/2:width,scale=typed?1:word?2:1;
            require(extent>0&&(!word||width%2==0)&&start==base&&start>=0&&start<end&&end<=2147483648L&&(end-start)*scale<=4096,"array.storage-range");
            List<Long> offsets=new ArrayList<>();offsets.add(0L);
            for(int axis=0;axis<rank;axis++){
                int n=f.path("shape").get(axis).asInt(),stride=f.path("strides").get(axis).asInt();long low=f.path("lowerBounds").get(axis).asLong();
                require(n>=1&&n<=256&&stride>=1&&stride<=4096&&low>=Integer.MIN_VALUE&&low+n-1<=Integer.MAX_VALUE,"array.bounds");
                count*=n;require(count<=256,"array.count");
                if(indices!=null)require(indices.size()==rank&&indices.get(axis).asLong()>=low&&indices.get(axis).asLong()<low+n,"array.index-range");
                List<Long> next=new ArrayList<>();for(long prior:offsets)for(int i=0;i<n;i++)next.add(prior+(long)i*stride);offsets=next;
            }
            Collections.sort(offsets);for(int i=1;i<offsets.size();i++)require(offsets.get(i)>=offsets.get(i-1)+extent,"array.overlap");
            require(offsets.get(offsets.size()-1)+extent<=end-start,"array.storage-range");
        }catch(Exception e){add(e.getMessage()==null?"array.invalid":e.getMessage(),path);}
    }
    private Sig sourceSig(JsonNode ref,String equipment,String path) {
        JsonNode s=resolve("source-definition",ref,path);if(s==null)return null;
        check(text(s,"equipmentInstanceId").equals(equipment),"value.equipment",path);
        check(!text(s,"accessMode").equals("write"),"source.not-readable",path);
        String type=text(s.path("rawRepresentation"),"valueType");
        if(text(s.path("rawRepresentation").path("codec"),"kind").equals("bcd16"))type="Int32";
        if(s.path("access").hasNonNull("bitOffset"))type="Boolean";
        if(s.has("fixedArray"))type="FixedArray";
        List<JsonNode> chain=viewChain(s);Set<String> lineage=new HashSet<>();for(JsonNode d:chain){lineage.add(key(d));if(text(d.path("view"),"kind").equals("bit"))type="Boolean";}
        return new Sig(type,s.path("unit"),lineage,text(s,"inputStage"),s.has("fixedArray")?s:null);
    }
    /** Read-only views inherit storage snapshots, never another acquisition. */
    private List<JsonNode> viewChain(JsonNode s) {
        List<JsonNode> chain=new ArrayList<>();Set<String> seen=new HashSet<>();
        while(s!=null){
            if(!seen.add(key(s))){add("view.cycle",key(s));break;}
            if(chain.size()>=17){add("view.depth",key(s));break;}
            chain.add(s);if(s.path("viewOf").isNull())break;
            if(!text(s,"schemaVersion").equals("2.10.0")){add("source.view-not-supported",key(s));break;}
            JsonNode next=resolve("source-definition",s.path("viewOf"),key(s));
            if(next==null)add("view.reference-missing",key(s));s=next;
        }
        return chain;
    }
    private String viewType(List<JsonNode> chain,int start) {
        for(int i=start;i<chain.size();i++)if(text(chain.get(i).path("view"),"kind").equals("bit"))return "Boolean";
        return text(chain.get(chain.size()-1).path("rawRepresentation"),"valueType");
    }
    private void view(JsonNode s) {
        String path=key(s);List<JsonNode> chain=viewChain(s);
        Map<String,Integer> bits=Map.of("Int16",16,"UInt16",16,"Int32",32,"UInt32",32,"Int64",64);
        for(int i=0;i+1<chain.size();i++){
            JsonNode child=chain.get(i),parent=chain.get(i+1);
            check(text(child,"sourceKind").equals("plc")&&parent.path("sourceKind").asText("plc").equals("plc"),"view.plc-only",path);
            check(text(child,"accessMode").equals("read")&&!text(parent,"accessMode").equals("write"),"view.readonly",path);
            check(text(parent,"status").equals("ready"),"view.parent-not-ready",path);
            for(String k:List.of("equipmentInstanceId","connectionProfileRef","accessProfileRef","access","rawRepresentation","inputStage","addressRadix"))check(child.path(k).equals(parent.path(k)),"view.snapshot-mismatch",path);
            String kind=text(child.path("view"),"kind");
            if(kind.equals("alias"))check(child.path("unit").equals(parent.path("unit")),"view.unit",path);
            else if(kind.equals("bit")){
                int width=bits.getOrDefault(viewType(chain,i+1),0);check(width>0,"view.integer-required",path);
                check(child.path("view").path("bitIndex").asInt()>=0&&child.path("view").path("bitIndex").asInt()<width,"view.bit-range",path);
                check(child.path("unit").equals(object().put("status","not-applicable")),"view.unit",path);
            }else add("view.kind",path);
        }
        JsonNode root=chain.get(chain.size()-1);
        check(bits.containsKey(text(root.path("rawRepresentation"),"valueType")),"view.integer-required",path);
        check(!root.has("fixedArray")&&!root.path("rawRepresentation").has("codec")&&!root.path("access").hasNonNull("bitOffset")&&!text(root.path("access"),"addressUnit").equals("bit"),"view.scalar-word-required",path);
    }
    private boolean covers(JsonNode refs,Set<String> sources) {
        Set<JsonNode> actual=new HashSet<>();refs.forEach(actual::add);
        for(String key:sources)for(JsonNode ref:docs.get(key).path("evidenceRefs"))if(!actual.contains(ref))return false;
        return true;
    }
    private static JsonNode unit(String code){return object().put("status","known").put("code",code);}
    private static boolean conversion(String from,String to){
        return Set.of("1/s:rpm","K:Cel","mN.m:N.m","Pa:kPa","kPa:Pa","bar:kPa","kPa:bar","Pa:bar","bar:Pa").contains(from+":"+to);
    }
    private void graph(JsonNode g){
        String path=key(g);Map<String,JsonNode> nodes=new LinkedHashMap<>();for(JsonNode n:g.path("nodes")){
            check(nodes.putIfAbsent(text(n,"nodeId"),n)==null,"graph.duplicate-node",path);evidence(n.path("evidenceRefs"),path);
        }
        Set<String> visiting=new HashSet<>();Map<String,Sig> done=new HashMap<>();
        for(String id:nodes.keySet())node(g,id,nodes,visiting,done);
        done.forEach((id,s)->{if(s!=null)graphSigs.put(path+"/"+id,s);});
    }
    private Sig node(JsonNode g,String id,Map<String,JsonNode> nodes,Set<String> visiting,Map<String,Sig> done){
        String path=key(g)+"/"+id;if(done.containsKey(id))return done.get(id);
        if(!visiting.add(id)){add("graph.cycle",path);return null;}
        JsonNode n=nodes.get(id);if(n==null){add("graph.node-missing",path);visiting.remove(id);return null;}
        Map<String,Sig> inputs=new LinkedHashMap<>();var fields=n.path("inputs").fields();
        while(fields.hasNext()){
            var f=fields.next();JsonNode e=f.getValue();Sig sig;
            if(text(e,"kind").equals("source"))sig=sourceSig(e.path("sourceRef"),text(g,"equipmentInstanceId"),path);
            else if(text(e,"kind").equals("graph")){
                JsonNode parent=resolve("value-graph",e.path("graphRef"),path);
                sig=parent==null?null:graphSigs.get(key(parent)+"/"+text(e,"nodeId"));
            }else sig=node(g,text(e,"nodeId"),nodes,visiting,done);
            inputs.put(f.getKey(),sig);
        }
        visiting.remove(id);
        if(inputs.values().stream().anyMatch(Objects::isNull)){done.put(id,null);return null;}
        Set<String> sources=new HashSet<>();inputs.values().forEach(v->sources.addAll(v.sources));check(covers(n.path("evidenceRefs"),sources),"graph.evidence-incomplete",path);
        Sig first=inputs.values().iterator().next(),result=null;String op=text(n,"op"),type=text(n,"valueType");JsonNode u=n.path("unit");
        switch(op){
            case "decode-u32-words" -> {
                for(Sig v:inputs.values()){
                    check(v.type.equals("UInt16")&&v.stage.equals("raw"),"graph.input-type",path);
                    check(text(v.unit,"status").equals("not-applicable"),"graph.input-unit",path);
                }
                check(!text(u,"status").equals("unknown"),"graph.output-unit",path);result=new Sig("UInt32",u,sources,"decoded",null);
            }
            case "identity" -> {
                check(type.equals(first.type),"graph.output-type",path);check(u.equals(first.unit),"graph.output-unit",path);result=first;
            }
            case "array-element" -> {
                check(first.array!=null,"array.input-type",path);
                if(first.array!=null){
                    array(first.array,n.path("indices"),path);String element=text(first.array.path("rawRepresentation"),"valueType");
                    check(type.equals(element),"graph.output-type",path);check(u.equals(first.unit),"graph.output-unit",path);
                    result=new Sig(element,u,sources,first.stage,null);
                }
            }
            case "bounded-selector" -> {
                int count=(int)inputs.keySet().stream().filter(k->k.startsWith("candidate")).count();
                for(int i=0;i<count;i++)check(inputs.containsKey("candidate"+i),"selector.candidates",path);
                for(String k:List.of("index","previousIndex"))if(inputs.containsKey(k)){
                    Sig v=inputs.get(k);check(Set.of("Int16","UInt16","Int32","UInt32","Int64").contains(v.type)&&v.unit.equals(unit("1")),"selector.index-type",path);
                }
                for(var e:inputs.entrySet())if(e.getKey().startsWith("candidate")){
                    check(e.getValue().type.equals(type)&&!type.equals("FixedArray"),"selector.candidate-type",path);
                    check(e.getValue().unit.equals(u)&&!text(u,"status").equals("unknown"),"selector.candidate-unit",path);
                }
                check(!n.has("defaultCandidate")||n.path("defaultCandidate").asInt()<count,"selector.default-range",path);
                result=new Sig(type,u,sources,inputs.entrySet().stream().filter(e->e.getKey().startsWith("candidate")).anyMatch(e->e.getValue().stage.equals("already-engineered"))?"already-engineered":"derived",null);
            }
            case "add","multiply","divide" -> {
                for(Sig v:inputs.values())check(NUM.contains(v.type),"graph.input-type",path);
                Sig left=inputs.get("left"),right=inputs.get("right");JsonNode output=u;
                Set<String> linear=Set.of("1","Pa","kPa","bar","rpm","1/s","N.m","mN.m");
                String l=text(left.unit,"code"),r=text(right.unit,"code");
                boolean known=text(left.unit,"status").equals("known")&&text(right.unit,"status").equals("known")&&linear.contains(l)&&linear.contains(r);
                boolean compatible=false;
                if(known){
                    if(op.equals("add")&&l.equals(r)){output=unit(l);compatible=true;}
                    else if(op.equals("multiply")&&(l.equals("1")||r.equals("1"))){output=unit(l.equals("1")?r:l);compatible=true;}
                    else if(op.equals("divide")&&r.equals("1")){output=unit(l);compatible=true;}
                    else if(op.equals("divide")&&l.equals(r)){output=unit("1");compatible=true;}
                }
                check(compatible,"graph.input-unit",path);check(u.equals(output),"graph.output-unit",path);check(type.equals("Decimal"),"graph.output-type",path);
                result=new Sig("Decimal",output,sources,"derived",null);
            }
            case "sqrt","clamp" -> {
                check(NUM.contains(first.type),"graph.input-type",path);
                check(text(first.unit,"status").equals("known"),"graph.input-unit",path);
                if(op.equals("sqrt"))check(first.unit.equals(unit("1")),"graph.input-unit",path);
                else check(new BigDecimal(text(n,"low")).compareTo(new BigDecimal(text(n,"high")))<=0,"graph.clamp-range",path);
                check(u.equals(first.unit),"graph.output-unit",path);
                check(type.equals("Decimal"),"graph.output-type",path);
                result=new Sig("Decimal",u,sources,"derived",null);
            }
            case "subtract","linear","unit-convert" -> {
                for(Sig v:inputs.values())check(NUM.contains(v.type),"graph.input-type",path);
                JsonNode output=first.unit;
                if(op.equals("subtract")){
                    for(Sig v:inputs.values())check(v.unit.equals(first.unit),"graph.input-unit",path);
                    check(Set.of("Pa","kPa","bar","1").contains(text(output,"code")),"graph.input-unit",path);
                }else if(op.equals("unit-convert")){
                    check(conversion(text(n,"from"),text(n,"to"))&&first.unit.equals(unit(text(n,"from"))),"graph.input-unit",path);output=unit(text(n,"to"));
                }else if(first.stage.equals("already-engineered")){
                    check(new BigDecimal(text(n,"factor")).compareTo(BigDecimal.ONE)==0&&new BigDecimal(text(n,"offset")).signum()==0,"mapping.double-transform",path);
                }
                check(u.equals(output)&&text(u,"status").equals("known"),"graph.output-unit",path);check(type.equals("Decimal"),"graph.output-type",path);result=new Sig("Decimal",u,sources,"derived",null);
            }
            default -> add("capability.unknown-op",path);
        }
        done.put(id,result);return result;
    }
    private Sig transforms(Sig input,JsonNode transforms,String path,boolean write){
        String type=input.type;JsonNode u=input.unit;
        for(JsonNode t:transforms)switch(text(t,"op")){
            case "linear" -> {
                check(NUM.contains(type),"transform.input",path);
                if(!write&&input.stage.equals("already-engineered"))check(new BigDecimal(text(t,"factor")).compareTo(BigDecimal.ONE)==0&&new BigDecimal(text(t,"offset")).signum()==0,"mapping.double-transform",path);
                type="Decimal";
            }
            case "unit-convert" -> {
                check(NUM.contains(type)&&u.equals(unit(text(t,"from")))&&conversion(text(t,"from"),text(t,"to")),"transform.unit",path);
                type="Decimal";u=unit(text(t,"to"));
            }
            case "cast" -> {
                String dest=text(t,"to");
                check(NUM.contains(dest)?NUM.contains(type):type.equals(dest),"transform.input",path);type=dest;
            }
            case "bit-select" -> {
                int bits=switch(type){case "Int16","UInt16"->16;case "Int32","UInt32"->32;case "Int64"->64;default->0;};
                check(!write&&bits>t.path("index").asInt(),"transform.bit",path);type="Boolean";u=object().put("status","not-applicable");
            }
            case "enum-map" -> {
                check(!write&&NUM.contains(type),"transform.input",path);Set<BigDecimal> values=new HashSet<>();
                for(JsonNode entry:t.path("entries"))check(values.add(new BigDecimal(text(entry,"raw")).stripTrailingZeros()),"transform.enum-duplicate",path);
                type="String";u=object().put("status","not-applicable");
            }
            default -> add("capability.unknown-op",path);
        }
        return new Sig(type,u,input.sources,input.stage,null);
    }
    private void mappings(){
        Set<String> bound=new HashSet<>(),ids=new HashSet<>();Map<String,Set<String>> coverage=new HashMap<>();
        for(JsonNode d:docs.values())if(text(d,"kind").equals("mapping-set")){
            String path=key(d);JsonNode target=resolve("target-instance",d.path("targetInstanceRef"),path);if(target==null)continue;
            check(text(d,"equipmentInstanceId").equals(text(target,"equipmentInstanceId")),"mapping.equipment",path);
            JsonNode sem=resolve("semantic-definition",target.path("semanticDefinitionRef"),path);if(sem==null)continue;
            for(JsonNode m:d.path("mappings")){
                String mp=path+"/"+text(m,"mappingId");check(ids.add(text(m,"mappingId")),"mapping.duplicate-id",mp);evidence(m.path("evidenceRefs"),mp);
                String mid=LogicalStructure.pathKey(m.path("memberPath"));JsonNode member=null;
                try{member=LogicalStructure.resolve(sem,m.path("memberPath"));}catch(IllegalArgumentException e){add(e.getMessage(),mp);}
                check(member!=null,"mapping.member",mp);check(bound.add(key(target)+"/"+mid),"mapping.duplicate-target",mp);coverage.computeIfAbsent(key(target),k->new HashSet<>()).add(mid);
                JsonNode v=m.path("valueRef");Sig sig;
                if(text(v,"kind").equals("source"))sig=sourceSig(v.path("sourceRef"),text(d,"equipmentInstanceId"),mp);
                else{
                    JsonNode g=resolve("value-graph",v.path("graphRef"),mp);sig=g==null?null:graphSigs.get(key(g)+"/"+text(v,"nodeId"));
                    if(g!=null)check(text(g,"equipmentInstanceId").equals(text(d,"equipmentInstanceId")),"value.equipment",mp);
                }
                check(sig!=null,"graph.node-missing",mp);if(sig==null||member==null)continue;
                check(covers(m.path("evidenceRefs"),sig.sources),"mapping.evidence-incomplete",mp);
                check(!sig.type.equals("FixedArray"),"array.whole-mapping",mp);Sig out=transforms(sig,m.path("transform"),mp,false);
                check(out.type.equals(text(member,"valueType")),"mapping.type",mp);check(m.path("outputUnit").equals(member.path("unit")),"mapping.unit",mp);
                // Receiver requires confirmed units; authoring may preserve unknown as a warning.
                check(!text(out.unit,"status").equals("unknown")&&out.unit.equals(m.path("outputUnit")),"mapping.unit-conversion-required",mp);
            }
        }
        for(JsonNode t:docs.values())if(text(t,"kind").equals("target-instance")){
            JsonNode sem=resolve("semantic-definition",t.path("semanticDefinitionRef"),key(t));if(sem!=null)try{for(String member:LogicalStructure.layout(sem).leaves().keySet())check(coverage.getOrDefault(key(t),Set.of()).contains(member),"mapping.incomplete-object",key(t));}catch(IllegalArgumentException e){add(e.getMessage(),key(t));}
        }
    }
    private void writes() throws Exception {
        Set<String> members=new HashSet<>(),destinations=new HashSet<>();
        for(JsonNode d:docs.values())if(text(d,"kind").equals("write-definition")){
            String path=key(d);JsonNode t=resolve("target-instance",d.path("targetInstanceRef"),path),s=resolve("source-definition",d.path("destinationRef"),path);
            if(t==null||s==null)continue;JsonNode sem=resolve("semantic-definition",t.path("semanticDefinitionRef"),path);if(sem==null)continue;
            String mid=text(d.path("memberPath").path(0),"memberId");JsonNode m=null;for(JsonNode x:sem.path("members"))if(text(x,"memberId").equals(mid))m=x;
            check(m!=null,"write.member",path);
            if(m!=null&&LogicalStructure.container(m)){add("write.logical-structure-unsupported",path);continue;}if(m==null)continue;
            check(text(t,"equipmentInstanceId").equals(text(d,"equipmentInstanceId"))&&text(s,"equipmentInstanceId").equals(text(d,"equipmentInstanceId")),"write.equipment",path);
            check(Set.of("write","read-write").contains(text(s,"accessMode"))&&Set.of("plc","solution-tag").contains(text(s,"sourceKind")),"write.destination-readonly",path);
            check(!s.has("fixedArray")&&!s.path("rawRepresentation").has("codec"),"write.destination-unsupported",path);
            Set<JsonNode> actual=new HashSet<>();d.path("evidenceRefs").forEach(actual::add);
            for(JsonNode ref:s.path("evidenceRefs"))check(actual.contains(ref),"write.evidence-incomplete",path);
            for(JsonNode ref:t.path("evidenceRefs"))check(actual.contains(ref),"write.evidence-incomplete",path);
            check(members.add(key(t)+"/"+mid),"write.duplicate-member",path);
            JsonNode loc=s.path("access");if(text(s,"sourceKind").equals("solution-tag")){ObjectNode location=object();location.set("solutionInstanceRef",loc.path("solutionInstanceRef"));location.set("tagPath",loc.path("tagPath"));loc=location;}
            String destination=text(s,"equipmentInstanceId")+"/"+text(s,"connectionProfileRef")+"/"+text(s,"accessProfileRef")+"/"+sha(bytes(loc));
            check(destinations.add(destination),"write.duplicate-destination",path);
            Sig out=transforms(new Sig(text(m,"valueType"),m.path("unit"),Set.of(),"semantic",null),d.path("transform"),path,true);
            check(out.type.equals(text(s.path("rawRepresentation"),"valueType")),"write.output-type",path);
            check(out.unit.equals(s.path("unit"))&&!text(out.unit,"status").equals("unknown"),"write.output-unit",path);
        }
    }
}
