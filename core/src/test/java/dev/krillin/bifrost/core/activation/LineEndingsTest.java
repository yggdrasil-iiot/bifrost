package dev.krillin.bifrost.core.activation;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;

class LineEndingsTest {
    static byte[] b(String s) { return s.getBytes(StandardCharsets.UTF_8); }

    @Test void aConversionEitherWayIsNamedAndAnythingElseIsNot() {
        String lfSha = Sha256.hex(b("a: 1\nb: 2\n")), crlfSha = Sha256.hex(b("a: 1\r\nb: 2\r\n"));
        assertTrue(LineEndings.explainMismatch(b("a: 1\r\nb: 2\r\n"), lfSha), "sealed LF, checked out CRLF");
        assertTrue(LineEndings.explainMismatch(b("a: 1\nb: 2\n"), crlfSha), "sealed CRLF, normalized to LF");
        assertFalse(LineEndings.explainMismatch(b("a: 1\nb: 2\n"), lfSha), "an exact match is not a mismatch");
        assertFalse(LineEndings.explainMismatch(b("a: 1\r\nb: 3\r\n"), lfSha), "a real edit is not a conversion");
        assertTrue(LineEndings.explainMismatch(b("a: 1\r\nb: 2\n"), crlfSha), "mixed endings that differ only at line ends");
        assertFalse(LineEndings.explainMismatch(b("a: 1\nb: 2 \n"), crlfSha), "trailing whitespace is an edit");
    }

    @Test void conversionsTouchOnlyLineEnds() {
        assertArrayEquals(b("x\ny\r"), LineEndings.toLf(b("x\r\ny\r")));
        assertArrayEquals(b("\r\nx\r\ny\r\n"), LineEndings.toCrlf(b("\nx\r\ny\n")));
    }
}
