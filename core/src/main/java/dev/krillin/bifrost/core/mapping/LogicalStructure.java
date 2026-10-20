package dev.krillin.bifrost.core.mapping;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import java.util.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;

/** Independent bounded logical layout. No native memory offsets or Python implementation. */
final class LogicalStructure {
    record Leaf(JsonNode member,JsonNode path) {}
    record Layout(Map<String,Leaf> leaves,List<JsonNode> definitions) {}
    static boolean container(JsonNode n){return Set.of("Structure","StructureArray").contains(text(n,"valueType"));}
    static String pathKey(JsonNode p){
        if(p.size()==1&&text(p.get(0),"kind").equals("member"))return text(p.get(0),"memberId");
        ArrayNode key=JSON.createArrayNode();
        for(JsonNode ep:p){ObjectNode x=object();x.put("kind",text(ep,"kind"));if(text(ep,"kind").equals("member"))x.put("memberId",text(ep,"memberId"));else x.set("indices",ep.path("indices"));key.add(x);}
        return key.toString();
    }
    static void preflight(JsonNode model){preflightNodes(model.path("members"),1,new int[]{0});}
    private static void preflightNodes(JsonNode nodes,int depth,int[] count){
        require(depth<=8,"structure.depth");
        for(JsonNode n:nodes){require(++count[0]<=256,"structure.size");if(n.has("members"))preflightNodes(n.path("members"),depth+1,count);}
    }
    static Layout layout(JsonNode model){
        Map<String,Leaf> leaves=new LinkedHashMap<>();List<JsonNode> definitions=new ArrayList<>();
        if(!text(model,"schemaVersion").equals("2.12.0")){
            for(JsonNode n:model.path("members")){ArrayNode p=JSON.createArrayNode();p.add(object().put("kind","member").put("memberId",text(n,"memberId")));require(leaves.put(text(n,"memberId"),new Leaf(n,p))==null,"semantic.duplicate");definitions.add(n);}
            return new Layout(leaves,definitions);
        }
        preflight(model);
        walk(model.path("members"),List.of(JSON.createArrayNode()),1,leaves,definitions);
        return new Layout(leaves,definitions);
    }
    private static void walk(JsonNode nodes,List<ArrayNode> paths,int depth,Map<String,Leaf> leaves,List<JsonNode> defs){
        require(depth<=8,"structure.depth");Set<String> ids=new HashSet<>();
        for(JsonNode n:nodes){
            require(ids.add(text(n,"memberId")),"semantic.duplicate");defs.add(n);require(defs.size()<=256,"structure.size");
            List<ArrayNode> next=new ArrayList<>();
            for(ArrayNode parent:paths){ArrayNode p=parent.deepCopy();p.add(object().put("kind","member").put("memberId",text(n,"memberId")));next.add(p);}
            if(text(n,"valueType").equals("Structure"))walk(n.path("members"),next,depth+1,leaves,defs);
            else if(text(n,"valueType").equals("StructureArray")){
                JsonNode shape=n.path("shape"),bounds=n.path("lowerBounds");require(shape.size()==bounds.size(),"structure.array-rank");
                long count=1;for(int k=0;k<shape.size();k++){require(shape.get(k).isIntegralNumber()&&bounds.get(k).isIntegralNumber(),"structure.array-rank");count*=shape.get(k).asLong();require(count<=256&&bounds.get(k).asLong()+shape.get(k).asLong()-1<=Integer.MAX_VALUE,"structure.array-range");}
                List<ArrayNode> expanded=new ArrayList<>();
                for(ArrayNode p:next)indices(n,0,JSON.createArrayNode(),p,expanded);
                require(expanded.size()<=256,"structure.size");walk(n.path("members"),expanded,depth+1,leaves,defs);
            }else for(ArrayNode p:next){require(leaves.size()<256,"structure.size");leaves.put(pathKey(p),new Leaf(n,p));}
        }
    }
    private static void indices(JsonNode n,int k,ArrayNode ix,ArrayNode path,List<ArrayNode> out){
        if(k==n.path("shape").size()){ArrayNode p=path.deepCopy();ObjectNode ep=object().put("kind","index");ep.set("indices",ix);p.add(ep);out.add(p);return;}
        long low=n.path("lowerBounds").get(k).asLong(),size=n.path("shape").get(k).asLong();
        for(long i=low;i<low+size;i++){ArrayNode next=ix.deepCopy();next.add((int)i);indices(n,k+1,next,path,out);}
    }
    static JsonNode resolve(JsonNode model,JsonNode path){
        JsonNode nodes=model.path("members");int i=0;
        while(i<path.size()){
            JsonNode ep=path.get(i++);require(text(ep,"kind").equals("member"),"mapping.member-path");
            JsonNode n=null;for(JsonNode candidate:nodes)if(text(candidate,"memberId").equals(text(ep,"memberId")))n=candidate;
            require(n!=null,"mapping.member");
            if(text(n,"valueType").equals("StructureArray")){
                require(i<path.size()&&text(path.get(i),"kind").equals("index"),"structure.index-required");
                JsonNode ix=path.get(i++).path("indices");require(ix.size()==n.path("shape").size(),"structure.array-rank");
                for(int k=0;k<ix.size();k++){require(ix.get(k).isIntegralNumber(),"structure.index-range");long v=ix.get(k).asLong(),b=n.path("lowerBounds").get(k).asLong(),s=n.path("shape").get(k).asLong();require(v>=b&&v<b+s,"structure.index-range");}
            }
            if(container(n)){require(i<path.size(),"structure.whole-mapping");nodes=n.path("members");}
            else{require(i==path.size(),"mapping.member-path");return n;}
        }
        throw new IllegalArgumentException("structure.whole-mapping");
    }
    static JsonNode signature(JsonNode n){
        ObjectNode sig=object();if(!container(n)){for(String k:List.of("role","valueType","unit"))sig.set(k,n.get(k));return sig;}
        sig.put("valueType",text(n,"valueType"));ObjectNode members=object();
        for(JsonNode child:n.path("members")){ObjectNode item=object();item.put("semanticId",text(child,"semanticId"));item.set("signature",signature(child));members.set(text(child,"memberId"),item);}
        sig.set("members",members);if(text(n,"valueType").equals("StructureArray")){sig.set("shape",n.path("shape"));sig.set("lowerBounds",n.path("lowerBounds"));}return sig;
    }
}
