package dev.krillin.bifrost.core.mapping;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.*;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;

/** Receiver-owned bounded dependency gate. Wire-only; no producer code dependency. */
final class GraphDependencies {
    private static String graphKey(JsonNode g){return text(g,"id")+"@"+text(g,"version");}
    static List<JsonNode> order(Collection<JsonNode> documents){
        List<JsonNode> graphs=documents.stream().filter(d->text(d,"kind").equals("value-graph")).toList();
        boolean external=graphs.stream().anyMatch(g->{for(JsonNode n:g.path("nodes"))for(JsonNode e:n.path("inputs"))if(text(e,"kind").equals("graph"))return true;return false;});
        if(!external)return graphs;
        require(graphs.stream().mapToInt(g->g.path("nodes").size()).sum()<=8192,"graph.dependency-size");
        Map<String,JsonNode> by=new TreeMap<>();Map<String,Set<String>> dependencies=new TreeMap<>();
        for(JsonNode g:graphs){by.put(graphKey(g),g);dependencies.put(graphKey(g),new HashSet<>());}
        for(JsonNode g:graphs)for(JsonNode n:g.path("nodes"))for(JsonNode e:n.path("inputs"))if(text(e,"kind").equals("graph")){
            require(text(g,"schemaVersion").equals("2.17.0"),"graph.endpoint-version");
            String target=graphKey(e.path("graphRef"));JsonNode parent=by.get(target);
            require(parent!=null,"reference.missing");require(text(parent,"equipmentInstanceId").equals(text(g,"equipmentInstanceId")),"value.equipment");
            List<JsonNode> nodes=new ArrayList<>();for(JsonNode x:parent.path("nodes"))if(text(x,"nodeId").equals(text(e,"nodeId")))nodes.add(x);
            require(nodes.size()==1,"graph.node-missing");require(!text(nodes.get(0),"valueType").equals("FixedArray"),"graph.reference-scalar-required");
            dependencies.get(graphKey(g)).add(target);
        }
        Set<String> pending=new TreeSet<>(by.keySet()),finished=new HashSet<>();List<JsonNode> output=new ArrayList<>();
        Map<String,Integer> depth=new HashMap<>(),height=new HashMap<>();
        while(!pending.isEmpty()){
            List<String> ready=pending.stream().filter(k->finished.containsAll(dependencies.get(k))).toList();
            require(!ready.isEmpty(),"graph.dependency-cycle");
            for(String k:ready){
                int d=1+dependencies.get(k).stream().mapToInt(depth::get).max().orElse(0);require(d<=32,"graph.dependency-depth");depth.put(k,d);
                JsonNode g=by.get(k);Map<String,JsonNode> nodes=new TreeMap<>();for(JsonNode n:g.path("nodes"))nodes.put(text(n,"nodeId"),n);
                Set<String> todo=new TreeSet<>(nodes.keySet()),done=new HashSet<>();
                for(JsonNode n:nodes.values())for(JsonNode e:n.path("inputs"))if(text(e,"kind").equals("node"))require(nodes.containsKey(text(e,"nodeId")),"graph.node-missing");
                while(!todo.isEmpty()){
                    List<String> nr=todo.stream().filter(id->{for(JsonNode e:nodes.get(id).path("inputs"))if(text(e,"kind").equals("node")&&!done.contains(text(e,"nodeId")))return false;return true;}).toList();
                    require(!nr.isEmpty(),"graph.cycle");
                    for(String id:nr){
                        int h=0;for(JsonNode e:nodes.get(id).path("inputs")){
                            String kind=text(e,"kind");if(kind.equals("node"))h=Math.max(h,height.get(k+"/"+text(e,"nodeId")));
                            else if(kind.equals("graph"))h=Math.max(h,height.get(graphKey(e.path("graphRef"))+"/"+text(e,"nodeId")));
                        }
                        require(h+1<=128,"graph.path-depth");height.put(k+"/"+id,h+1);done.add(id);todo.remove(id);
                    }
                }
                output.add(g);finished.add(k);pending.remove(k);
            }
        }
        return output;
    }
}
