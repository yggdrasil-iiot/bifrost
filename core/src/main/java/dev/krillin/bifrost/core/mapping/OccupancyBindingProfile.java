package dev.krillin.bifrost.core.mapping;
import com.fasterxml.jackson.databind.*;
import java.util.*;
import java.util.regex.Pattern;
import static dev.krillin.bifrost.core.mapping.MappingJson.*;
/** Bifrost's own reader of a forseti occupancy binding, profile 0.1.0: the data file an evidence-artifact (schemaVersion 1.1.0)
 *  carries, naming how an attribution rule accepts MES occupancy events. Read from the published bytes alone, no forseti code.
 *  An unsupported version, a missing or extra field, an empty value, or an identity pattern outside the syntax common to Java
 *  and ECMA-262 is refused with the caller's code (the rule validators pass attribution.binding-profile). schemaSha256 is
 *  checked for its form only; whether it equals the job's built-in schema is the job's start-up check. */
public record OccupancyBindingProfile(String topic,String schemaId,String schemaSha256,String identityScheme,String identityPattern,
                                      String enterBizStep,String leaveBizStep,List<String> correctionReasons,List<String> sources) {
 public static final String VERSION="0.1.0",SCHEMA_ID="urn:forseti:schema:occupancy:1.0.0",ID_PREFIX="occupancy-binding-",
  MEDIA_TYPE="application/vnd.forseti.occupancy-binding+json";
 static final Set<String> REASONS=Set.of("urn:epcglobal:cbv:er:did_not_occur","urn:epcglobal:cbv:er:incorrect_data");
 private static final Set<String> FIELDS=Set.of("profileVersion","topic","format","identity","enter","leave","correction","timestampBasis","sources");
 public static OccupancyBindingProfile parse(byte[] bytes,String code){
  JsonNode b;
  try{b=JSON.readTree(bytes);}catch(Exception e){throw new IllegalArgumentException(code);}
  require(b!=null&&b.isObject()&&names(b).equals(FIELDS),code);
  require(text(b,"profileVersion").equals(VERSION)&&nonEmpty(b,"topic")&&text(b,"timestampBasis").equals("eventTime"),code);
  JsonNode f=b.path("format"),id=b.path("identity"),enter=b.path("enter"),leave=b.path("leave"),c=b.path("correction");
  require(names(f).equals(Set.of("schemaId","schemaSha256"))&&text(f,"schemaId").equals(SCHEMA_ID)&&f.path("schemaSha256").isTextual()&&text(f,"schemaSha256").matches("[0-9a-f]{64}"),code);
  require(names(id).equals(Set.of("scheme","pattern"))&&text(id,"scheme").equals("mes-unit-id")&&nonEmpty(id,"pattern"),code);
  require(names(enter).equals(Set.of("bizStep"))&&nonEmpty(enter,"bizStep")&&names(leave).equals(Set.of("bizStep"))&&nonEmpty(leave,"bizStep"),code);
  require(names(c).equals(Set.of("errorDeclaration","reasons"))&&text(c,"errorDeclaration").equals("reissue-same-event-id"),code);
  List<String> reasons=strings(c.path("reasons"),code),sources=strings(b.path("sources"),code);
  require(REASONS.containsAll(reasons),code);
  require(BindingPattern.accepted(text(id,"pattern")),code);
  return new OccupancyBindingProfile(text(b,"topic"),text(f,"schemaId"),text(f,"schemaSha256"),text(id,"scheme"),text(id,"pattern"),
   text(enter,"bizStep"),text(leave,"bizStep"),reasons,sources);
 }
 static Set<String> names(JsonNode n){Set<String> s=new HashSet<>();if(n.isObject())n.fieldNames().forEachRemaining(s::add);return s;}
 static boolean nonEmpty(JsonNode n,String k){return n.path(k).isTextual()&&!n.path(k).asText().isEmpty();}
 /** A non-empty array of distinct non-empty strings. */
 static List<String> strings(JsonNode a,String code){
  require(a.isArray()&&a.size()>0,code);List<String> out=new ArrayList<>();
  for(JsonNode x:a){require(x.isTextual()&&!x.asText().isEmpty()&&!out.contains(x.asText()),code);out.add(x.asText());}
  return List.copyOf(out);
 }
 /** The regex subset of spec "Binding profiles": literals, '.', bracket classes with ranges and negation, a backslash before a
  *  non-alphanumeric ASCII character as a literal, the quantifiers * + ? {m} {m,} {m,n}, alternation and non-capturing groups.
  *  Anchors, lookaround, backreferences, flags, named or capturing groups, shorthand or property or POSIX classes, lazy or
  *  possessive quantifiers, Java's class intersection '&&', a bare '{', nesting deeper than MAX_DEPTH groups and any surrogate code unit
  *  (Java reads a pair as one code point, ECMA-262 without the u flag as two) are refused. Java compiles the accepted expression last. */
 static final class BindingPattern {
  /** Deepest (?: nesting accepted; far more than a unit-id pattern needs, and it bounds the recursion. */
  static final int MAX_DEPTH=32;
  private final String s;private int i,depth;
  private BindingPattern(String s){this.s=s;}
  static boolean accepted(String p){
   if(p.isEmpty())return false;
   for(int k=0;k<p.length();k++)if(Character.isSurrogate(p.charAt(k)))return false;
   BindingPattern b=new BindingPattern(p);
   try{b.alternation();if(b.i!=p.length())return false;Pattern.compile(p);return true;}catch(RuntimeException e){return false;}
  }
  private boolean at(char c){return i<s.length()&&s.charAt(i)==c;}
  private void alternation(){sequence();while(at('|')){i++;sequence();}}
  private void sequence(){while(i<s.length()&&!at('|')&&!at(')')){atom();quantifier();}}
  private void atom(){
   char c=s.charAt(i);
   switch(c){
    case '(' -> {require(s.startsWith("(?:",i)&&depth<MAX_DEPTH,"group");i+=3;depth++;alternation();depth--;require(at(')'),"group");i++;}
    case '[' -> charClass();
    case '\\' -> escape();
    case '.' -> i++;
    case '^','$',')','*','+','?','{','}','|',']' -> throw new IllegalArgumentException("meta");
    default -> i++;
   }
  }
  private void escape(){require(i+1<s.length(),"escape");char n=s.charAt(i+1);require(n<128&&!Character.isLetterOrDigit(n),"escape");i+=2;}
  private void charClass(){
   i++;if(at('^'))i++;require(!at(']'),"class");
   while(!at(']')){
    require(i<s.length(),"class");classChar();
    if(at('-')&&i+1<s.length()&&s.charAt(i+1)!=']'){i++;classChar();}
   }
   i++;
  }
  private void classChar(){
   char c=s.charAt(i);
   if(c=='\\')escape();
   else{require(c!='['&&c!=']'&&!(c=='&'&&i+1<s.length()&&s.charAt(i+1)=='&'),"class");i++;}
  }
  private void quantifier(){
   if(i>=s.length())return;
   char c=s.charAt(i);
   if(c=='*'||c=='+'||c=='?')i++;
   else if(c=='{'){
    int close=s.indexOf('}',i);require(close>i,"quantifier");String q=s.substring(i+1,close);
    require(q.matches("[0-9]+|[0-9]+,|[0-9]+,[0-9]+"),"quantifier");
    if(q.contains(",")&&!q.endsWith(","))require(Long.parseLong(q.split(",")[0])<=Long.parseLong(q.split(",")[1]),"quantifier");
    i=close+1;
   }else return;
   require(!(at('?')||at('+')||at('*')||at('{')),"quantifier");
  }
 }
}
