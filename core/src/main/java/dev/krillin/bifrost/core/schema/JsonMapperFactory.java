package dev.krillin.bifrost.core.schema;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.module.SimpleModule;
import java.io.IOException;

/** Factory for an ObjectMapper with a module that serializes/deserializes SemVer as an "x.y.z" string. */
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
        return new ObjectMapper().registerModule(m);
    }
}
