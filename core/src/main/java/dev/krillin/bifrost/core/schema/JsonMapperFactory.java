package dev.krillin.bifrost.core.schema;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.util.DefaultIndenter;
import com.fasterxml.jackson.core.util.DefaultPrettyPrinter;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.module.SimpleModule;
import java.io.IOException;

/** Factory for an ObjectMapper with a module that serializes/deserializes SemVer as an "x.y.z" string
 *  and Instant as an ISO-8601 string.
 *
 *  <p>Instant is hand-written rather than pulled in with jackson-datatype-jsr310 for the same reason
 *  the SemVer handling above it is: two optional fields on one record do not justify a dependency that
 *  would change how every JSON in the reactor treats time. An unparseable value throws out of the
 *  deserializer, which the caller turns into its own coded, fail-closed error. */
public final class JsonMapperFactory {
    private JsonMapperFactory() {}

    public static ObjectMapper create() {
        SimpleModule m = new SimpleModule();
        m.addSerializer(SemVer.class, new JsonSerializer<SemVer>() {
            @Override public void serialize(SemVer v, JsonGenerator g, SerializerProvider p) throws IOException {
                g.writeString(v.toString());
            }
        });
        m.addDeserializer(SemVer.class, new JsonDeserializer<SemVer>() {
            @Override public SemVer deserialize(JsonParser p, DeserializationContext c) throws IOException {
                return SemVer.parse(p.getValueAsString());
            }
        });
        m.addSerializer(java.time.Instant.class, new JsonSerializer<java.time.Instant>() {
            @Override public void serialize(java.time.Instant v, JsonGenerator g, SerializerProvider p) throws IOException {
                g.writeString(v.toString());
            }
        });
        m.addDeserializer(java.time.Instant.class, new JsonDeserializer<java.time.Instant>() {
            @Override public java.time.Instant deserialize(JsonParser p, DeserializationContext c) throws IOException {
                return java.time.Instant.parse(p.getValueAsString());
            }
        });
        return new ObjectMapper().registerModule(m);
    }

    /** Pretty JSON that ends every line with LF. Jackson's default pretty printer uses line.separator, so the
     *  same value would be CRLF bytes on Windows and LF on Linux — and a file whose bytes are hashed must not
     *  depend on the OS that wrote it. Every pretty-printed file in the reactor goes through here. */
    public static ObjectWriter prettyWriter(ObjectMapper mapper) {
        return mapper.writer(new DefaultPrettyPrinter().withObjectIndenter(new DefaultIndenter("  ", "\n")));
    }
}
