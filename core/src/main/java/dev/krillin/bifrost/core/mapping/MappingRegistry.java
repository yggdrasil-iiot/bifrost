package dev.krillin.bifrost.core.mapping;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import dev.krillin.bifrost.core.activation.*;
import dev.krillin.bifrost.core.identity.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;

/** Immutable signed approval + atomic file release. Does not touch an activation ledger or runtime. */
public final class MappingRegistry {
    private final Path registry;
    private List<JsonNode> lifecycleHistory=List.of();
    private List<JsonNode> templateHistory=List.of();
    private List<JsonNode> recordHistory=List.of();
    private final Clock clock;
    private final Runnable beforeCommit;
    private java.util.function.Consumer<String> fault = point -> {};
    // Package-private deterministic interruption seam; never exposed by CLI or HTTP.
    MappingRegistry faults(java.util.function.Consumer<String> hook){fault=hook;return this;}
    private final AnchorStore anchors;
    public MappingRegistry(Path registry){this(registry,Clock.systemUTC(),()->{});}
    public MappingRegistry(Path registry,Clock clock,Runnable beforeCommit){this(registry,clock,beforeCommit,null);}
    /** anchors keeps the highest head version reached per stream, outside mappings/; null means registry/anchor/. */
    public MappingRegistry(Path registry,Clock clock,Runnable beforeCommit,AnchorStore anchors){this.registry=registry.toAbsolutePath().normalize();this.clock=clock;this.beforeCommit=beforeCommit;this.anchors=anchors==null?new FileAnchorStore(this.registry):anchors;}
    /** The two principals who sign a head version, and how long it stays fresh. */
    public record HeadSigners(String by,Path byKey,String approvedBy,Path approvedKey,Duration lifetime){}
    public static final Duration DEFAULT_HEAD_LIFETIME=Duration.ofDays(90);
    private static final Duration CLOCK_SKEW=Duration.ofHours(24);
    private Path mappings(){return registry.resolve("mappings");}
    private static void id(String s){require(s!=null&&s.matches("[a-z][a-z0-9._-]{0,127}"),"mapping.id");}
    private static void version(String s){require(s!=null&&s.matches("(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)"),"mapping.version");}
    private Path headPath(String ref){id(ref);return mappings().resolve("heads").resolve(ref+".json");}
    private JsonNode head(String ref) throws Exception {
        Path p=headPath(ref);return Files.exists(p)?read(safe(mappings(),"heads/"+ref+".json")):JSON.nullNode();
    }
    private void base(JsonNode submission) throws Exception {
        String ref=text(submission,"streamId");
        JsonNode current=head(ref),expected=submission.path("baseRelease");
        require(current.equals(expected),"mapping.base-conflict");
        if(!current.isNull())require(text(verifyRelease(text(current,"id"),text(current,"version"),text(current,"sha256")),"streamId").equals(ref),"mapping.base-stream");
    }
    private interface Task {JsonNode run() throws Exception;}
    private JsonNode locked(Task task) throws Exception {
        Files.createDirectories(mappings());
        require(!Files.isSymbolicLink(registry),"mapping.registry-symlink");
        require(!Files.isSymbolicLink(mappings()),"mapping.registry-symlink");
        // Refuse redirected registry paths, including the lock and nested release parents.
        try(var walk=Files.walk(mappings())){for(Path p:walk.toList())require(!Files.isSymbolicLink(p),"mapping.registry-symlink");}
        try(FileChannel c=FileChannel.open(mappings().resolve(".lock"),StandardOpenOption.CREATE,StandardOpenOption.WRITE);FileLock lock=c.lock()){return task.run();}
    }
    private MappingBundle.Checked checked(Path folder) {
        var c=new MappingBundle().validate(folder);require(c.accepted(),"mapping.validation-refused:"+c.report().path("findings"));return c;
    }
    private void authorize(String proposer,String approver,String ref) {
        ActivationPolicy policy=ActivationPolicyStore.load(registry);ActivationAuthorizer a=new ActivationAuthorizer();
        require(!proposer.equals(approver),"mapping.approval.self");
        require(a.authorize(policy,proposer,ActivationAction.PUBLISH,"mapping-publication","mapping-release",ref).allowed(),"mapping.publish-denied");
        require(a.authorize(policy,approver,ActivationAction.APPROVE,"mapping-publication","mapping-release",ref).allowed(),"mapping.approve-denied");
    }
    private JsonNode changes(MappingBundle.Checked current) throws Exception {
        Map<String,JsonNode> prior=Map.of();JsonNode b=current.submission().path("baseRelease");
        if(!b.isNull()){
            Path payload=mappings().resolve("releases").resolve(text(b,"id")).resolve(text(b,"version")).resolve("payload");
            prior=checked(payload).documents();
        }
        requireCatalogCompatible(current.documents());
        return diffDocuments(prior,current.documents());
    }
    /** Derived from verified immutable history, including releases no longer at a head. */
    public JsonNode catalog() throws Exception {return locked(()->{requireNoTransactions();return catalogLocked();});}
    private static void catalogPaths(JsonNode nodes,ArrayNode prefix,Map<JsonNode,JsonNode> paths){
        for(JsonNode n:nodes){ArrayNode p=prefix.deepCopy();p.add(text(n,"memberId"));paths.put(n,p);catalogPaths(n.path("members"),p,paths);}
    }
    private ObjectNode catalogLocked() throws Exception {
        Map<String,ArrayNode> concepts=new TreeMap<>();ArrayNode releases=JSON.createArrayNode();List<JsonNode> events=new ArrayList<>(),recipes=new ArrayList<>(),recordRecipes=new ArrayList<>();
        Path dir=mappings().resolve("releases");
        if(Files.exists(dir))try(var ids=Files.list(dir)){
            for(Path rid:ids.sorted().toList()){
                require(Files.isDirectory(rid),"mapping.catalog-layout");id(rid.getFileName().toString());
                try(var versions=Files.list(rid)){
                    for(Path v:versions.sorted().toList()){
                        require(Files.isDirectory(v),"mapping.catalog-layout");version(v.getFileName().toString());
                        require(releases.size()<256,"mapping.catalog-release-limit");
                        String hash=sha(safe(v,"release.json"));
                        JsonNode release=verifyRelease(rid.getFileName().toString(),v.getFileName().toString(),hash);
                        ObjectNode origin=object().put("streamId",text(release,"streamId")).put("releaseId",text(release,"id"))
                            .put("releaseVersion",text(release,"version")).put("releaseSha256",hash);
                        releases.add(origin);
                        var payloadDocs=checked(v.resolve("payload")).documents();
                        for(JsonNode d:payloadDocs.values()){if(text(d,"kind").equals("semantic-lifecycle"))events.add(d);if(MappingTemplates.KINDS.contains(text(d,"kind")))recipes.add(d);if(Set.of("record-mapping","mapping-template","source-definition").contains(text(d,"kind")))recordRecipes.add(d);}
                        for(JsonNode d:new TreeMap<>(payloadDocs).values())if(text(d,"kind").equals("semantic-definition")){
                            Map<JsonNode,JsonNode> paths=new IdentityHashMap<>();catalogPaths(d.path("members"),JSON.createArrayNode(),paths);
                            for(JsonNode n:LogicalStructure.layout(d).definitions()){
                                String uri=text(n,"semanticId");JsonNode signature=LogicalStructure.signature(n);
                                ArrayNode variants=concepts.computeIfAbsent(uri,k->JSON.createArrayNode());
                                require(concepts.size()<=4096,"mapping.catalog-concept-limit");
                                ObjectNode variant=null;for(JsonNode x:variants)if(x.path("signature").equals(signature))variant=(ObjectNode)x;
                                if(variant==null){variant=object();variant.set("signature",signature);variant.set("occurrences",JSON.createArrayNode());variants.add(variant);}
                                ObjectNode occurrence=origin.deepCopy();occurrence.put("definitionId",text(d,"id")).put("definitionVersion",text(d,"version"))
                                    .put("memberId",text(n,"memberId")).put("label",text(n,"name"));
                                occurrence.set("definitionPath",paths.get(n));
                                ((ArrayNode)variant.path("occurrences")).add(occurrence);
                            }
                        }
                    }
                }
            }
        }
        // A head is an additional integrity anchor; history is retained even without heads.
        Path heads=mappings().resolve("heads");if(Files.exists(heads))try(var files=Files.list(heads)){
            for(Path p:files.sorted().toList()){String name=p.getFileName().toString();if(name.startsWith("."))continue;
                require(name.matches("[a-z][a-z0-9._-]{0,127}\\.json"),"mapping.catalog-head");String stream=name.substring(0,name.length()-5);JsonNode h=head(stream);
                require(text(verifyRelease(text(h,"id"),text(h,"version"),text(h,"sha256")),"streamId").equals(stream),"mapping.head-stream");
            }
        }
        ArrayNode entries=JSON.createArrayNode();boolean compatible=true;
        for(var e:concepts.entrySet()){boolean ok=e.getValue().size()==1;compatible&=ok;ObjectNode item=object().put("semanticId",e.getKey()).put("compatible",ok);item.set("variants",e.getValue());entries.add(item);}
        ObjectNode result=object().put("kind","semantic-catalog").put("schemaVersion","2.16.0").put("compatible",compatible)
            .put("scope","registry-history").put("activation","not-performed").put("execution","excluded");
        result.set("releases",releases);result.set("entries",entries);result.put("catalogSha256",sha(bytes(result)));
        require(bytes(result).length<=4*1024*1024,"mapping.catalog-report-limit");schema(result,"semantic-catalog");lifecycleHistory=List.copyOf(events);templateHistory=List.copyOf(recipes);RecordMappings.histories(recordRecipes);RecordFields.history(recordRecipes,recordRecipes);recordHistory=List.copyOf(recordRecipes);return result;
    }
    private void requireCatalogCompatible(Map<String,JsonNode> documents) throws Exception {
        JsonNode catalog=catalogLocked();require(catalog.path("compatible").asBoolean(),"mapping.semantic-history-conflict");
        Map<String,JsonNode> known=new HashMap<>();for(JsonNode e:catalog.path("entries"))known.put(text(e,"semanticId"),e.path("variants").get(0).path("signature"));
        RecordFields.history(documents.values(),recordHistory);RecordBroadcast.history(documents.values(),recordHistory);
        if(!recordHistory.isEmpty()||documents.values().stream().anyMatch(d->text(d,"kind").equals("record-mapping")))RecordMappings.validate(documents.values(),recordHistory,null);
        if(!templateHistory.isEmpty()||documents.values().stream().anyMatch(d->MappingTemplates.KINDS.contains(text(d,"kind"))))MappingTemplates.validate(documents.values(),templateHistory);
        if(!lifecycleHistory.isEmpty()||documents.values().stream().anyMatch(d->text(d,"kind").equals("semantic-lifecycle")))SemanticLifecycle.validate(MappingBundle.governanceDocuments(documents.values()),lifecycleHistory,known);
        for(JsonNode d:documents.values())if(text(d,"kind").equals("semantic-definition"))for(JsonNode n:LogicalStructure.layout(d).definitions()){
            String uri=text(n,"semanticId");require(!known.containsKey(uri)||known.get(uri).equals(LogicalStructure.signature(n)),"mapping.semantic-drift:"+uri);
        }
    }
    public JsonNode lifecycle() throws Exception {return locked(()->{
        requireNoTransactions();JsonNode catalog=catalogLocked();require(catalog.path("compatible").asBoolean(),"mapping.semantic-history-conflict");
        Map<String,JsonNode> known=new TreeMap<>();for(JsonNode e:catalog.path("entries"))known.put(text(e,"semanticId"),e.path("variants").get(0).path("signature"));
        var states=SemanticLifecycle.replay(lifecycleHistory,known);ArrayNode entries=JSON.createArrayNode(),events=JSON.createArrayNode(),impacts=JSON.createArrayNode(),eventReleases=JSON.createArrayNode();
        for(var e:known.entrySet()){ObjectNode s=states.get(e.getKey());if(s==null){s=object().put("semanticId",e.getKey()).put("state","active").put("revision",0);s.putNull("replacementSemanticId");s.putArray("history");}else s=s.deepCopy();s.set("signature",e.getValue());entries.add(s);}
        Map<String,JsonNode> unique=new TreeMap<>();for(JsonNode e:lifecycleHistory)unique.put(text(e,"id")+"@"+text(e,"version"),e);unique.values().forEach(events::add);
        for(JsonNode release:catalog.path("releases")){Path payload=mappings().resolve("releases").resolve(text(release,"releaseId")).resolve(text(release,"releaseVersion")).resolve("payload");boolean current=text(head(text(release,"streamId")),"sha256").equals(text(release,"releaseSha256"));
            var releaseDocs=new TreeMap<>(checked(payload).documents());for(JsonNode d:releaseDocs.values())if(text(d,"kind").equals("semantic-lifecycle")){ObjectNode origin=object().put("eventId",text(d,"id")).put("eventVersion",text(d,"version")).put("semanticId",text(d,"semanticId")).put("revision",d.path("revision").asInt());origin.set("release",release);eventReleases.add(origin);}
            for(JsonNode i:SemanticLifecycle.impacts(MappingBundle.governanceDocuments(releaseDocs.values()))){ObjectNode item=i.deepCopy();item.set("release",release);item.put("currentHead",current);impacts.add(item);}}
        ObjectNode out=object().put("kind","semantic-lifecycle-catalog").put("schemaVersion","2.18.0").put("scope","registry-history").put("execution","excluded").put("activation","not-performed");out.set("entries",entries);out.set("events",events);out.set("eventReleases",eventReleases);out.set("impacts",impacts);out.put("catalogSha256",sha(bytes(out)));require(bytes(out).length<=4*1024*1024,"lifecycle.report-limit");return out;
    });}
    private static String signingMessage(JsonNode payload) throws Exception {return "BIFROST_MAPPING_APPROVAL_V1\n"+sha(bytes(payload));}
    private Path attestationPath(String approvalId){id(approvalId);return mappings().resolve("attestations").resolve(approvalId+".dsse.json");}
    /** Verifies a release, then the DSSE envelope of its approval: both principals' registered keys, distinct, over
     *  a statement whose predicate is the release's receipt payload and whose subject is exactly its files[]. */
    public JsonNode verifyAttestation(String releaseId,String ver,String expected) throws Exception {
        return locked(()->{
            JsonNode r=verifyRelease(releaseId,ver,expected);JsonNode p=r.path("approval").path("payload");
            Path file=attestationPath(text(p,"approvalId"));require(Files.exists(file),"mapping.attestation-missing");
            byte[] body;
            try{body=Dsse.verify(read(safe(mappings(),mappings().relativize(file).toString().replace('\\','/'))),Dsse.IN_TOTO,AuthorizedKeys.load(registry),List.of(text(p,"proposedBy"),text(p,"approvedBy")));}
            catch(IdentityException e){throw new IllegalArgumentException("mapping.attestation-signature:"+e.rule());}
            JsonNode statement=JSON.readTree(body);MappingAttestation.matches(statement,r);return statement;
        });
    }
    public JsonNode approve(Path bundle,String approvalId,String by,Path byKey,String approvedBy,Path approvedKey) throws Exception {
        id(approvalId);id(by);id(approvedBy);
        return locked(()->{
            requireNoTransactions();var c=checked(bundle);base(c.submission());require(text(c.submission(),"proposedBy").equals(by),"mapping.proposer-mismatch");
            authorize(by,approvedBy,text(c.submission(),"streamId"));
            var signer=KeyFileLedgerSigner.create(by,byKey,approvedBy,approvedKey,AuthorizedKeys.load(registry),clock);
            require(signer.preflight().isEmpty(),"mapping.identity-refused:"+signer.preflight());
            JsonNode changes=changes(c);ObjectNode payload=object();payload.put("changeSha256",sha(bytes(changes)));payload.put("streamId",text(c.submission(),"streamId"));payload.put("approvalId",approvalId);payload.put("submissionId",text(c.submission(),"id"));payload.put("proposalId",text(c.proposal(),"id"));
            payload.put("proposalSha256",text(c.report(),"proposalSha256"));payload.put("bundleSha256",text(c.report(),"bundleSha256"));payload.set("baseRelease",c.submission().get("baseRelease"));
            payload.put("proposedBy",by);payload.put("approvedBy",approvedBy);payload.put("at",clock.instant().toString());payload.put("capability",MappingBundle.CAPABILITY);payload.put("execution","excluded");
            Signatures sig=signer.sign(signingMessage(payload));
            ObjectNode receipt=object();receipt.put("kind","mapping-approval");receipt.put("schemaVersion","2.9.0");receipt.set("payload",payload);receipt.set("changeAssessment",changes);receipt.put("payloadSha256",sha(bytes(payload)));
            receipt.put("proposerSignature",sig.activatorSig());receipt.put("approverSignature",sig.approverSig());schema(receipt,"mapping-approval");
            require(bytes(receipt).length<=4*1024*1024,"mapping.approval-limit");
            Path dest=mappings().resolve("approvals").resolve(approvalId+".json");require(!Files.exists(dest),"mapping.approval-id-conflict");
            // The in-toto attestation goes first: a crash between the two leaves an envelope no receipt refers to,
            // which a retry with the same approval id replaces; never a receipt without its attestation.
            byte[] statement=MappingAttestation.statement(c.files(),payload);Signatures dsse=signer.signRaw(Dsse.pae(Dsse.IN_TOTO,statement));
            JsonNode envelope=Dsse.envelope(Dsse.IN_TOTO,statement,List.of(new Dsse.Signature(by,dsse.activatorSig()),new Dsse.Signature(approvedBy,dsse.approverSig())));
            Path attestation=attestationPath(approvalId);Path staged=attestation.resolveSibling("."+UUID.randomUUID()+".pending");save(staged,envelope);
            Files.move(staged,attestation,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);fault.accept("attestation-written");
            Path pending=dest.resolveSibling("."+UUID.randomUUID()+".pending");save(pending,receipt);Files.move(pending,dest,StandardCopyOption.ATOMIC_MOVE);return receipt;
        });
    }
    private void verifyApproval(JsonNode receipt,boolean publication) throws Exception {
        schema(receipt,"mapping-approval");JsonNode p=receipt.path("payload");
        require(text(receipt,"payloadSha256").equals(sha(bytes(p)))&&text(p,"capability").equals(MappingBundle.CAPABILITY),"mapping.approval-digest");
        require(text(p,"changeSha256").equals(sha(bytes(receipt.path("changeAssessment")))),"mapping.approval-change-digest");
        Instant.parse(text(p,"at"));String by=text(p,"proposedBy"),approved=text(p,"approvedBy");require(!by.equals(approved),"mapping.approval.self");
        AuthorizedKeys auth=AuthorizedKeys.load(registry);byte[] msg=signingMessage(p).getBytes(StandardCharsets.UTF_8);
        var a=auth.verifying(by,msg,text(receipt,"proposerSignature"));var b=auth.verifying(approved,msg,text(receipt,"approverSignature"));
        require(a.isPresent()&&b.isPresent()&&!Arrays.equals(a.get().getEncoded(),b.get().getEncoded()),"mapping.approval-signature");
        if(publication){
            require(auth.validForPrincipal(by,clock.instant()).contains(a.get())&&auth.validForPrincipal(approved,clock.instant()).contains(b.get()),"mapping.approval-key-retired");
            authorize(by,approved,text(p,"streamId"));
        }
    }
    private Path headAttestationPath(String stream){id(stream);return mappings().resolve("head-attestations").resolve(stream+".dsse.json");}
    /** The verified freshness state of a stream: version 0 is a head that was never signed (or no head at all). */
    private record Fresh(MappingHeadAttestation.Head head,JsonNode release,long version,JsonNode predicate){}
    private JsonNode headPredicate(JsonNode envelope,MappingHeadAttestation.Head h,JsonNode release) throws Exception {
        JsonNode claimed;
        try{claimed=JSON.readTree(Base64.getDecoder().decode(text(envelope,"payload"))).path("predicate");}catch(Exception e){throw new IllegalArgumentException("mapping.head-attestation-statement");}
        String by=text(claimed,"publishedBy"),approved=text(claimed,"approvedBy");
        require(!by.isEmpty()&&!approved.isEmpty()&&!by.equals(approved),"mapping.head-attestation-statement");
        byte[] body;
        try{body=Dsse.verify(envelope,Dsse.IN_TOTO,AuthorizedKeys.load(registry),List.of(by,approved));}
        catch(IdentityException e){throw new IllegalArgumentException("mapping.head-attestation-signature:"+e.rule());}
        JsonNode p=MappingHeadAttestation.matches(JSON.readTree(body),h,release);
        // A retired key keeps verifying what it signed; the two principals must still hold the stream now.
        authorize(text(p,"publishedBy"),text(p,"approvedBy"),h.stream());return p;
    }
    /** finish: a writer may record the witness for a signed version one above it (a crash between the two writes). */
    private Fresh fresh(String stream,boolean finish) throws Exception {
        Optional<AnchorRecord> anchor=anchors.latest(MappingHeadAttestation.anchorTarget(stream));Path file=headAttestationPath(stream);
        if(!Files.exists(headPath(stream))){require(!Files.exists(file)&&anchor.isEmpty(),"mapping.head-rollback");return new Fresh(null,null,0,null);}
        String rel="heads/"+stream+".json";JsonNode node=read(safe(mappings(),rel));
        var h=new MappingHeadAttestation.Head(stream,node,Files.readAllBytes(safe(mappings(),rel)));
        JsonNode release=verifyRelease(text(node,"id"),text(node,"version"),text(node,"sha256"));require(text(release,"streamId").equals(stream),"mapping.head-stream");
        if(!Files.exists(file)){require(anchor.isEmpty(),"mapping.head-rollback");return new Fresh(h,release,0,null);}
        JsonNode p=headPredicate(read(safe(mappings(),"head-attestations/"+stream+".dsse.json")),h,release);long v=p.path("headVersion").asLong();
        long seq=anchor.map(AnchorRecord::seq).orElse(0L);
        if(finish&&v==seq+1){recordAnchor(stream,v,h.headBytes());seq=v;}
        require(anchor.isPresent()||seq==v,"mapping.head-anchor-missing");
        require(v>=seq,"mapping.head-rollback");require(v<=seq,"mapping.head-anchor-behind");
        require(anchors.latest(MappingHeadAttestation.anchorTarget(stream)).get().tailEntryHash().equals(sha(h.headBytes())),"mapping.head-anchor-tail-mismatch");
        return new Fresh(h,release,v,p);
    }
    private void recordAnchor(String stream,long version,byte[] headBytes) throws Exception {
        try{anchors.record(new AnchorRecord(MappingHeadAttestation.anchorTarget(stream),version,sha(headBytes)));}
        catch(IllegalStateException e){throw new IllegalArgumentException(String.valueOf(e.getMessage()).startsWith("anchor.seq-regression")?"mapping.head-rollback":"mapping.head-anchor-tail-mismatch");}
    }
    private KeyFileLedgerSigner headSigner(HeadSigners s,String stream){
        id(s.by());id(s.approvedBy());Duration l=s.lifetime();
        require(l!=null&&l.compareTo(Duration.ofDays(1))>=0&&l.compareTo(Duration.ofDays(366))<=0,"mapping.head-expiry-bounds");
        authorize(s.by(),s.approvedBy(),stream);
        var signer=KeyFileLedgerSigner.create(s.by(),s.byKey(),s.approvedBy(),s.approvedKey(),AuthorizedKeys.load(registry),clock);
        require(signer.preflight().isEmpty(),"mapping.identity-refused:"+signer.preflight());return signer;
    }
    private Path stageHeadAttestation(MappingHeadAttestation.Head h,String approvalId,Fresh before,String cause,HeadSigners s,KeyFileLedgerSigner signer) throws Exception {
        Instant now=clock.instant().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        JsonNode previous=before.version()==0?null:object().put("headVersion",before.version()).set("release",before.head().head());
        byte[] statement=MappingHeadAttestation.statement(h,before.version()+1,now,now.plus(s.lifetime()),cause,previous,approvalId,s.by(),s.approvedBy());
        Signatures sig=signer.signRaw(Dsse.pae(Dsse.IN_TOTO,statement));
        JsonNode envelope=Dsse.envelope(Dsse.IN_TOTO,statement,List.of(new Dsse.Signature(s.by(),sig.activatorSig()),new Dsse.Signature(s.approvedBy(),sig.approverSig())));
        Path pending=mappings().resolve("head-attestations").resolve("."+UUID.randomUUID()+".pending");save(pending,envelope);force(pending);
        fault.accept("head-attestation-staged");return pending;
    }
    private void commitHeadAttestation(Path pending,String stream,long version,byte[] headBytes) throws Exception {
        Files.move(pending,headAttestationPath(stream),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
        fault.accept("head-attestation-moved");recordAnchor(stream,version,headBytes);fault.accept("head-anchored");
    }
    private ObjectNode headReport(String kind,Fresh f){
        ObjectNode r=object().put("kind",kind).put("streamId",f.head().stream()).put("headVersion",f.version());
        for(String k:List.of("cause","signedAt","expires","publishedBy","approvedBy"))r.put(k,text(f.predicate(),k));
        r.set("head",f.head().head());r.put("activation","not-performed").put("execution","excluded");return r;
    }
    /** TUF rules for one stream head: signed by two current principals, not below the witness, not expired. */
    public JsonNode verifyHead(String stream) throws Exception {return locked(()->{
        requireNoTransactions();Fresh f=fresh(stream,false);require(f.head()!=null,"mapping.head-missing");require(f.version()>0,"mapping.head-attestation-missing");
        Instant now=clock.instant(),signed=MappingHeadAttestation.instant(f.predicate(),"signedAt"),expires=MappingHeadAttestation.instant(f.predicate(),"expires");
        // A verifier clock far behind the signer cannot judge expiry honestly; a fast one fails as expired.
        require(!signed.isAfter(now.plus(CLOCK_SKEW)),"mapping.head-clock-behind");require(now.isBefore(expires),"mapping.head-expired");
        return headReport("mapping-head-verification",f).put("now",now.toString());
    });}
    /** Renews an attested head (same release, version + 1, new expiry) or attests a legacy one as version 1. */
    public JsonNode signHead(String stream,HeadSigners s) throws Exception {return locked(()->{
        requireNoTransactions();var signer=headSigner(s,stream);Fresh f=fresh(stream,true);require(f.head()!=null,"mapping.head-missing");
        Path pending=stageHeadAttestation(f.head(),text(f.release().path("approval").path("payload"),"approvalId"),f,f.version()==0?"migrate":"renew",s,signer);
        commitHeadAttestation(pending,stream,f.version()+1,f.head().headBytes());
        return headReport("mapping-head-signature",fresh(stream,false));
    });}
    public JsonNode publish(Path bundle,String releaseId,String ver,String approvalId) throws Exception {return publish(bundle,releaseId,ver,approvalId,null);}
    /** signers null keeps the unsigned publication, allowed only on a stream that never had a signed head. */
    public JsonNode publish(Path bundle,String releaseId,String ver,String approvalId,HeadSigners signers) throws Exception {
        id(releaseId);id(approvalId);version(ver);
        return locked(()->{
            requireNoTransactions();var c=checked(bundle);base(c.submission());String stream=text(c.submission(),"streamId");
            JsonNode receipt=read(safe(mappings(),"approvals/"+approvalId+".json"));verifyApproval(receipt,true);JsonNode a=receipt.path("payload");
            require(text(a,"streamId").equals(text(c.submission(),"streamId"))&&text(a,"submissionId").equals(text(c.submission(),"id"))&&text(a,"proposedBy").equals(text(c.submission(),"proposedBy"))&&text(a,"proposalId").equals(text(c.proposal(),"id"))&&text(a,"proposalSha256").equals(text(c.report(),"proposalSha256"))&&text(a,"bundleSha256").equals(text(c.report(),"bundleSha256"))&&a.get("baseRelease").equals(c.submission().get("baseRelease")),"mapping.approval-stale");
            require(text(a,"changeSha256").equals(sha(bytes(changes(c)))),"mapping.approval-change-stale");
            KeyFileLedgerSigner signer=null;Fresh before=null;
            if(signers==null)require(!Files.exists(headAttestationPath(stream))&&anchors.latest(MappingHeadAttestation.anchorTarget(stream)).isEmpty(),"mapping.head-signers-required");
            else{signer=headSigner(signers,stream);before=fresh(stream,false);}
            Path dest=mappings().resolve("releases").resolve(releaseId).resolve(ver);
            require(!Files.exists(dest),"mapping.release-id-conflict");Files.createDirectories(dest.getParent());
            Path staging=Files.createTempDirectory(mappings(),".staging-");Path payload=staging.resolve("payload");Files.createDirectories(payload);
            for(String rel:c.files().keySet()){
                Path f=payload.resolve(rel);Files.createDirectories(f.getParent());Files.copy(safe(bundle,rel),f);
            }
            var staged=checked(payload);require(text(staged.report(),"bundleSha256").equals(text(c.report(),"bundleSha256")),"mapping.staging-digest");
            ObjectNode release=object();release.put("streamId",text(c.submission(),"streamId"));release.put("kind","mapping-release");release.put("schemaVersion","2.9.0");release.put("id",releaseId);release.put("version",ver);release.put("proposalId",text(c.proposal(),"id"));release.put("submissionId",text(c.submission(),"id"));
            release.put("proposalSha256",text(c.report(),"proposalSha256"));release.put("bundleSha256",text(c.report(),"bundleSha256"));release.set("baseRelease",c.submission().get("baseRelease"));release.set("approval",receipt);
            ArrayNode files=JSON.createArrayNode();new TreeMap<>(c.files()).forEach((path,hash)->files.add(object().put("path","payload/"+path).put("sha256",hash)));release.set("files",files);
            release.put("publishedBy","bifrost");release.put("at",clock.instant().toString());release.put("activation","not-performed");release.put("execution","excluded");schema(release,"mapping-release");require(bytes(release).length<=4*1024*1024,"mapping.release-limit");save(staging.resolve("release.json"),release);
            beforeCommit.run();
            String tx=UUID.randomUUID().toString();
            ObjectNode head=object().put("id",releaseId).put("version",ver).put("sha256",sha(staging.resolve("release.json")));
            Path pendingHead=signers==null?null:stageHeadAttestation(new MappingHeadAttestation.Head(stream,head,bytes(head)),approvalId,before,"publish",signers,signer);
            ObjectNode intent=object().put("kind","mapping-publication-intent").put("version",signers==null?1:2).put("streamId",text(c.submission(),"streamId"))
                .put("id",releaseId).put("releaseVersion",ver).put("sha256",sha(staging.resolve("release.json"))).put("staging",staging.getFileName().toString());
            intent.set("baseRelease",c.submission().get("baseRelease"));
            if(pendingHead!=null)intent.put("headAttestation",pendingHead.getFileName().toString());
            Path journal=mappings().resolve("transactions").resolve(tx+".json");save(journal,intent);force(journal);
            fault.accept("intent-written");
            // No non-atomic fallback: on unsupported FS, refuse with the previous head intact.
            Files.move(staging,dest,StandardCopyOption.ATOMIC_MOVE);
            fault.accept("release-moved");
            require(text(head,"sha256").equals(sha(dest.resolve("release.json"))),"mapping.staging-digest");
            Path current=headPath(text(c.submission(),"streamId"));Files.createDirectories(current.getParent());
            Path temp=current.resolveSibling("."+UUID.randomUUID()+".json");save(temp,head);Files.move(temp,current,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
            fault.accept("head-moved");
            if(pendingHead!=null)commitHeadAttestation(pendingHead,stream,before.version()+1,bytes(head));
            Files.delete(journal);
            return release;
        });
    }
    public JsonNode verifyRelease(String releaseId,String ver,String expected) throws Exception {
        id(releaseId);version(ver);Path root=mappings().resolve("releases").resolve(releaseId).resolve(ver);
        return verifyRoot(root,releaseId,ver,expected);
    }
    private JsonNode verifyRoot(Path root,String releaseId,String ver,String expected) throws Exception {
        for(Path cursor=root;cursor!=null&&cursor.startsWith(mappings());cursor=cursor.getParent())require(!Files.isSymbolicLink(cursor),"mapping.release-symlink");
        JsonNode r=read(safe(root,"release.json"));schema(r,"mapping-release");
        require(text(r,"id").equals(releaseId)&&text(r,"version").equals(ver)&&sha(root.resolve("release.json")).equals(expected),"mapping.release-digest");
        verifyApproval(r.path("approval"),false);
        Set<String> paths=new HashSet<>();for(JsonNode f:r.path("files")){String path=text(f,"path");require(paths.add(path)&&sha(safe(root,path)).equals(text(f,"sha256")),"mapping.release-file");}
        var c=checked(root.resolve("payload"));require(text(c.report(),"bundleSha256").equals(text(r,"bundleSha256"))&&text(c.report(),"proposalSha256").equals(text(r,"proposalSha256")),"mapping.release-bundle");
        require(text(r,"proposalId").equals(text(c.proposal(),"id"))&&text(r,"submissionId").equals(text(c.submission(),"id"))&&text(r,"streamId").equals(text(c.submission(),"streamId")),"mapping.release-identity");
        JsonNode a=r.path("approval").path("payload");
        require(text(a,"bundleSha256").equals(text(r,"bundleSha256"))&&text(a,"proposalSha256").equals(text(r,"proposalSha256"))&&text(a,"streamId").equals(text(r,"streamId"))&&text(a,"submissionId").equals(text(r,"submissionId"))&&a.get("baseRelease").equals(r.get("baseRelease")),"mapping.release-approval");
        require(paths.size()==c.files().size()&&paths.containsAll(c.files().keySet().stream().map(x->"payload/"+x).toList()),"mapping.release-inventory");
        return r;
    }
    public JsonNode status(String streamId) throws Exception {return locked(()->statusLocked(streamId));}
    private JsonNode statusLocked(String streamId) throws Exception {
        id(streamId);ObjectNode result=object();result.put("kind","mapping-publication-status");result.put("schemaVersion","2.9.0");result.put("streamId",streamId);
        JsonNode h=head(streamId);result.set("head",h);result.set("release",h.isNull()?JSON.nullNode():verifyRelease(text(h,"id"),text(h,"version"),text(h,"sha256")));
        ArrayNode approvals=JSON.createArrayNode();Path dir=mappings().resolve("approvals");
        if(Files.isDirectory(dir))try(var walk=Files.list(dir)){
            for(Path p:walk.filter(x->x.getFileName().toString().endsWith(".json")).sorted().toList()){
                JsonNode r=read(safe(mappings(),"approvals/"+p.getFileName()));if(text(r.path("payload"),"streamId").equals(streamId)){verifyApproval(r,false);approvals.add(r);}
            }
        }
        if(!h.isNull())require(text(result.path("release"),"streamId").equals(streamId),"mapping.head-stream");
        result.set("approvals",approvals);result.put("activation","not-performed");result.put("execution","excluded");return result;
    }

    private static void force(Path path) throws Exception {
        try(FileChannel channel=FileChannel.open(path,StandardOpenOption.WRITE)){channel.force(true);}
    }
    private List<Path> transactions() throws Exception {
        Path dir=mappings().resolve("transactions");if(!Files.exists(dir))return List.of();
        require(!Files.isSymbolicLink(dir),"mapping.journal-symlink");
        try(var files=Files.list(dir)){return files.sorted().toList();}
    }
    private void requireNoTransactions() throws Exception {require(transactions().isEmpty(),"mapping.recovery-required");}
    /** Explicit restart recovery. A signed immutable release is verified before head CAS. */
    public JsonNode recover() throws Exception {return locked(()->{
        ArrayNode actions=JSON.createArrayNode();
        for(Path journal:transactions()){
            require(journal.getFileName().toString().matches("[0-9a-f-]{36}\\.json"),"mapping.journal-name");
            JsonNode j=read(safe(mappings(),"transactions/"+journal.getFileName()));
            // Version 2 also names the head attestation the publication signed before its intent was written.
            int jv=j.path("version").asInt();
            require((j.size()==8&&jv==1||j.size()==9&&jv==2)&&j.path("version").isInt()&&text(j,"kind").equals("mapping-publication-intent"),"mapping.journal-format");
            String rid=text(j,"id"),ver=text(j,"releaseVersion"),stream=text(j,"streamId"),hash=text(j,"sha256"),stage=text(j,"staging"),signed=jv==2?text(j,"headAttestation"):null;
            id(rid);id(stream);version(ver);require(hash.matches("[0-9a-f]{64}")&&stage.matches("\\.staging-[a-zA-Z0-9-]+")&&(signed==null||signed.matches("\\.[0-9a-f-]{36}\\.pending")),"mapping.journal-path");
            Path dest=mappings().resolve("releases").resolve(rid).resolve(ver),staging=mappings().resolve(stage);
            Path root=Files.exists(dest)?dest:staging;
            JsonNode r=verifyRoot(root,rid,ver,hash);
            requireCatalogCompatible(checked(root.resolve("payload")).documents());
            require(text(r,"streamId").equals(stream)&&r.path("baseRelease").equals(j.path("baseRelease")),"mapping.journal-release");
            ObjectNode target=object().put("id",rid).put("version",ver).put("sha256",hash);
            JsonNode current=head(stream);require(current.equals(j.path("baseRelease"))||current.equals(target),"mapping.recovery-base-conflict");
            if(!current.equals(target)){
                base(r);
                // Complete only the originally authorized intent; no new approval/activation occurs.
                if(!Files.exists(dest)){Files.createDirectories(dest.getParent());Files.move(staging,dest,StandardCopyOption.ATOMIC_MOVE);}
                Path h=headPath(stream);Files.createDirectories(h.getParent());Path temp=h.resolveSibling("."+UUID.randomUUID()+".json");
                save(temp,target);force(temp);Files.move(temp,h,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
            }
            if(signed!=null){
                // Recovery signs nothing: it places the envelope the publication already signed, then its witness.
                Path pending=mappings().resolve("head-attestations").resolve(signed);
                if(Files.exists(pending)){
                    var head=new MappingHeadAttestation.Head(stream,target,bytes(target));
                    JsonNode p=headPredicate(read(safe(mappings(),"head-attestations/"+signed)),head,verifyRelease(rid,ver,hash));
                    commitHeadAttestation(pending,stream,p.path("headVersion").asLong(),head.headBytes());
                }else fresh(stream,true);
            }
            Files.delete(journal);actions.add(object().put("releaseId",rid).put("state","recovered").put("headAttestation",signed==null?"unsigned":"placed"));
        }
        return object().put("kind","mapping-maintenance").put("operation","recover").put("execution","excluded").put("activation","not-performed").set("actions",actions);
    });}
    private String treeDigest(Path path) throws Exception {
        Map<String,String> pins=new TreeMap<>();
        try(var walk=Files.walk(path)){for(Path p:walk.sorted().toList()){
            require(!Files.isSymbolicLink(p),"mapping.gc-symlink");
            if(Files.isRegularFile(p))pins.put(path.equals(p)?"file":path.relativize(p).toString().replace('\\','/'),sha(p));
            else require(Files.isDirectory(p),"mapping.gc-file");
        }}return manifestDigest(pins);
    }
    private JsonNode gcPlan(long graceSeconds) throws Exception {
        require(graceSeconds>=3600&&graceSeconds<=31536000,"mapping.gc-grace");requireNoTransactions();
        try(var walk=Files.walk(mappings())){for(Path p:walk.toList())require(!Files.isSymbolicLink(p),"mapping.gc-symlink");}
        // Preserve every immutable approval/release (including unheaded history), not only current head.
        Path releases=mappings().resolve("releases");
        if(Files.exists(releases))try(var ids=Files.list(releases)){
            for(Path rid:ids.toList())if(Files.isDirectory(rid))try(var versions=Files.list(rid)){
                for(Path version:versions.toList())if(Files.isDirectory(version)&&version.getFileName().toString().matches("[0-9]+\\.[0-9]+\\.[0-9]+")){
                    Path metadata=safe(mappings(),mappings().relativize(version.resolve("release.json")).toString().replace('\\','/'));
                    verifyRelease(rid.getFileName().toString(),version.getFileName().toString(),sha(metadata));
                }
            }
        }
        Path approvals=mappings().resolve("approvals");if(Files.exists(approvals))try(var files=Files.list(approvals)){
            for(Path p:files.filter(x->x.getFileName().toString().matches("[a-z][a-z0-9._-]*\\.json")).toList())verifyApproval(read(safe(mappings(),"approvals/"+p.getFileName())),false);
        }
        Path heads=mappings().resolve("heads");if(Files.exists(heads))try(var files=Files.list(heads)){
            for(Path p:files.filter(x->x.getFileName().toString().matches("[a-z][a-z0-9._-]*\\.json")).toList())statusLocked(p.getFileName().toString().replaceFirst("\\.json$",""));
        }
        ArrayNode candidates=JSON.createArrayNode();Path attestations=mappings().resolve("attestations"),headAttestations=mappings().resolve("head-attestations");
        for(Path dir:List.of(mappings(),approvals,heads,attestations,headAttestations))if(Files.exists(dir)){
            require(!Files.isSymbolicLink(dir),"mapping.gc-symlink");
            try(var files=Files.list(dir)){for(Path p:files.sorted().toList()){
                String name=p.getFileName().toString();boolean recognized=dir.equals(mappings())?name.matches("\\.staging-[a-zA-Z0-9-]+"):
                    name.matches("\\.[0-9a-f-]{36}\\.(pending|json)");
                if(!recognized)continue;
                require(!Files.isSymbolicLink(p),"mapping.gc-symlink");
                if(Files.getLastModifiedTime(p).toInstant().plusSeconds(graceSeconds).isAfter(clock.instant()))continue;
                candidates.add(object().put("path",mappings().relativize(p).toString().replace('\\','/')).put("sha256",treeDigest(p)));
            }}
        }
        Map<String,String> roots=new TreeMap<>();for(Path dir:List.of(releases,approvals,heads,attestations,headAttestations))if(Files.exists(dir))try(var walk=Files.walk(dir)){
            for(Path p:walk.filter(Files::isRegularFile).toList())roots.put(mappings().relativize(p).toString().replace('\\','/'),sha(p));
        }
        ObjectNode plan=object().put("rootsSha256",manifestDigest(roots)).put("kind","mapping-maintenance").put("operation","gc").put("graceSeconds",graceSeconds).put("execution","excluded").put("activation","not-performed");
        plan.set("candidates",candidates);plan.put("planSha256",sha(bytes(plan)));return plan;
    }
    /** Reversible quarantine only. A stale plan cannot sweep files created by another operation. */
    public JsonNode gc(long graceSeconds,String expectedPlan) throws Exception {return locked(()->{
        ObjectNode plan=(ObjectNode)gcPlan(graceSeconds);if(expectedPlan==null){plan.put("dryRun",true);return plan;}
        require(text(plan,"planSha256").equals(expectedPlan),"mapping.gc-plan-conflict");
        for(JsonNode c:plan.path("candidates")){
            Path source=mappings().resolve(text(c,"path")),dest=mappings().resolve("quarantine").resolve(UUID.randomUUID().toString()).resolve(source.getFileName());
            Files.createDirectories(dest.getParent());Files.move(source,dest,StandardCopyOption.ATOMIC_MOVE);fault.accept("gc-quarantined");
        }
        plan.put("dryRun",false);plan.put("action","quarantine");return plan;
    });}

    public static JsonNode diff(Path before,Path after){
        var a=new MappingBundle().validate(before);var b=new MappingBundle().validate(after);require(a.accepted()&&b.accepted(),"mapping.diff-invalid");
        return diffDocuments(a.documents(),b.documents());
    }
    private static JsonNode diffDocuments(Map<String,JsonNode> before,Map<String,JsonNode> after){
        ArrayNode changes=JSON.createArrayNode();Set<String> keys=new TreeSet<>(before.keySet());keys.addAll(after.keySet());
        for(String key:keys)difference(key,"",before.get(key),after.get(key),changes);
        ObjectNode d=object();d.put("kind","mapping-receiver-diff");d.set("changes",changes);d.put("reviewRequired",!changes.isEmpty());d.put("execution","excluded");return d;
    }
    private static void difference(String key,String path,JsonNode a,JsonNode b,ArrayNode out){
        if(Objects.equals(a,b))return;
        if(a!=null&&b!=null&&a.isObject()&&b.isObject()){
            Set<String> names=new TreeSet<>();a.fieldNames().forEachRemaining(names::add);b.fieldNames().forEachRemaining(names::add);
            for(String n:names)difference(key,path+"/"+n,a.get(n),b.get(n),out);return;
        }
        if(a!=null&&b!=null&&a.isArray()&&b.isArray()&&!a.isEmpty()&&!b.isEmpty()){
            for(String stable:List.of("memberId","mappingId","nodeId")){
                boolean matches=true;for(JsonNode x:a)matches&=x.has(stable);for(JsonNode x:b)matches&=x.has(stable);
                if(matches){
                    Map<String,JsonNode> left=new TreeMap<>(),right=new TreeMap<>();
                    for(JsonNode x:a)left.put(text(x,stable),x);for(JsonNode x:b)right.put(text(x,stable),x);
                    Set<String> ids=new TreeSet<>(left.keySet());ids.addAll(right.keySet());for(String id:ids)difference(key,path+"/"+id,left.get(id),right.get(id),out);
                    return;
                }
            }
        }
        String cat=path.contains("/access")?"access":path.contains("rawRepresentation")||path.contains("fixedArray")?"decode":path.contains("transform")?"transform":path.endsWith("/name")||path.endsWith("/label")||path.endsWith("/description")?"presentation":path.contains("members")||path.contains("/unit")?"meaning":key.startsWith("value-graph")?"graph":"definition";
        ObjectNode c=object().put("target",key).put("path",path.isEmpty()?"/":path).put("category",cat);c.set("before",a==null?JSON.nullNode():a);c.set("after",b==null?JSON.nullNode():b);out.add(c);
    }
}
