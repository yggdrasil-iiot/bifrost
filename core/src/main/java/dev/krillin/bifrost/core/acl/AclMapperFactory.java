package dev.krillin.bifrost.core.acl;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

/** ObjectMapper for ACL policy — rejects unknown fields (enforcement mechanism for the unknown-field lint rule). */
public final class AclMapperFactory {
    private AclMapperFactory() {}
    public static ObjectMapper create() {
        return new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true);
    }
}
