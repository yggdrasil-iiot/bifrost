package dev.krillin.bifrost.core.schema;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

class MemberAasShapeTest {
  @Test void memberCarriesSemanticIdAndRange() {
    Member m = new Member("Rpm", "Double", "urn:bifrost:sem:Mixer/Rpm", new Range(0, 3000));
    assertEquals("urn:bifrost:sem:Mixer/Rpm", m.semanticId());
    assertEquals(3000.0, m.range().high());
  }

  @Test void nonNumericMemberHasNullRange() {
    Member m = new Member("Running", "Boolean", "urn:bifrost:sem:Mixer/Running", null);
    assertNull(m.range());
  }
}
