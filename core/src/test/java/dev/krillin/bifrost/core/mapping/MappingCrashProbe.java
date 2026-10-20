package dev.krillin.bifrost.core.mapping;
import java.nio.file.Path;
/** Test executable: abrupt JVM termination after a named durable filesystem step. */
public final class MappingCrashProbe {
 public static void main(String[] a) throws Exception {
  MappingRegistry r=new MappingRegistry(Path.of(a[0])).faults(point->{if(point.equals(a[4]))Runtime.getRuntime().halt(77);});
  r.publish(Path.of(a[1]),"release","1.0.0","approval-1");
 }
}
