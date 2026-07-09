package dev.krillin.bifrost.core.activation;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.util.List;
import dev.krillin.bifrost.core.conformance.MasterSpecStore;
import dev.krillin.bifrost.core.schema.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class RecipeArtifactResolverTest {
    @Test void resolvesBytesAndSha(@TempDir Path reg) throws Exception {
        MasterSpec spec = new MasterSpec("mix-recipe","1.0.0","Line1","Line1-Mixer","1.0.0",
            List.of(new Setpoint("Rpm","Double",1500)));
        Path f = new MasterSpecStore().file(reg,"mix-recipe","1.0.0");
        Files.createDirectories(f.getParent());
        JsonMapperFactory.create().writeValue(f.toFile(), spec);
        var r = new RecipeArtifactResolver(reg).resolve("recipe","mix-recipe","1.0.0").orElseThrow();
        assertEquals(f, r.path());
        assertEquals(Sha256.hex(Files.readAllBytes(f)), r.sha256());
    }
    @Test void absentVersionIsEmpty(@TempDir Path reg) {
        assertTrue(new RecipeArtifactResolver(reg).resolve("recipe","mix-recipe","9.9.9").isEmpty());
    }
    @Test void nonRecipeKindIsEmpty(@TempDir Path reg) {
        assertTrue(new RecipeArtifactResolver(reg).resolve("equipment","x","1.0.0").isEmpty());
    }
    @Test void invalidJsonIsEmpty(@TempDir Path reg) throws Exception {
        Path f = new MasterSpecStore().file(reg,"broken","1.0.0");
        Files.createDirectories(f.getParent());
        Files.writeString(f, "{ not valid master spec");
        assertTrue(new RecipeArtifactResolver(reg).resolve("recipe","broken","1.0.0").isEmpty());
    }
}
