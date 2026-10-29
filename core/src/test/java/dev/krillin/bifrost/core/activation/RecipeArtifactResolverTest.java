package dev.krillin.bifrost.core.activation;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.util.List;
import dev.krillin.bifrost.core.conformance.MasterSpecStore;
import dev.krillin.bifrost.core.schema.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class RecipeArtifactResolverTest {
    static final String DEF_REF = "0123456789abcdef0123456789abcdef01234567";
    static byte[] spec() throws Exception {
        return JsonMapperFactory.create().writeValueAsBytes(new MasterSpec("mix-recipe","1.0.0","Line1","Line1-Mixer","1.0.0",
            List.of(new Setpoint("Rpm","Double",1500))));
    }
    static void publish(Path reg, byte[] bytes) throws Exception {
        new RecipeDefinitionStore(reg).publish(PublishedRecipe.MANIFEST_KIND, "mix-recipe", "1.0.0", bytes, DEF_REF,
                Sha256.hex(bytes), "recipes/mix-recipe.json", 1L);
    }
    @Test void resolvesThePublishedCanonicalAndItsPublication(@TempDir Path reg) throws Exception {
        publish(reg, spec());
        Path dir = reg.resolve("recipe/mix-recipe/1.0.0");
        var r = new RecipeArtifactResolver(reg).resolve("recipe","mix-recipe","1.0.0").orElseThrow();
        assertEquals(dir.resolve("recipe-setpoints.yaml"), r.path());
        assertEquals(Sha256.hex(spec()), r.sha256());
        assertEquals(new PublicationRef(Sha256.hex(Files.readAllBytes(dir.resolve("manifest.json"))), DEF_REF, null), r.publication());
    }
    @Test void absentVersionIsEmpty(@TempDir Path reg) {
        assertTrue(new RecipeArtifactResolver(reg).resolve("recipe","mix-recipe","9.9.9").isEmpty());
    }
    @Test void nonRecipeKindIsEmpty(@TempDir Path reg) {
        assertTrue(new RecipeArtifactResolver(reg).resolve("equipment","x","1.0.0").isEmpty());
    }
    @Test void anUnpublishedSpecFileIsRefusedByName(@TempDir Path reg) throws Exception {
        Path f = new MasterSpecStore().file(reg,"mix-recipe","1.0.0");
        Files.createDirectories(f.getParent());
        Files.write(f, spec());
        var u = assertThrows(ArtifactResolver.Unresolvable.class,
                () -> new RecipeArtifactResolver(reg).resolve("recipe","mix-recipe","1.0.0"));
        assertEquals("activation.publication.missing", u.rule());
    }
    @Test void aPublishedCanonicalThatIsNotAMasterSpecIsUnresolved(@TempDir Path reg) throws Exception {
        publish(reg, "{ not valid master spec".getBytes());
        var u = assertThrows(ArtifactResolver.Unresolvable.class,
                () -> new RecipeArtifactResolver(reg).resolve("recipe","mix-recipe","1.0.0"));
        assertEquals("activation.artifact.unresolved", u.rule());
    }
}
