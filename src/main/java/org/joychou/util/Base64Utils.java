package org.joychou.util;

import java.util.Base64;

/**
 * Bounded Base64 decoding for attacker-controlled input.
 */
public class Base64Utils {

    private Base64Utils() {
    }

    /**
     * Decode standard Base64 after rejecting input longer than maxEncodedLength characters.
     * Invalid alphabet/padding is still rejected by the strict JDK decoder.
     *
     * @param encoded          Base64 text (null behaves like Base64.Decoder#decode: NullPointerException)
     * @param maxEncodedLength maximum accepted length of the encoded text
     * @return decoded bytes
     * @throws IllegalArgumentException if the input is too long or not valid Base64
     */
    public static byte[] decodeBounded(String encoded, int maxEncodedLength) {
        if (encoded != null && encoded.length() > maxEncodedLength) {
            throw new IllegalArgumentException("Base64 input exceeds " + maxEncodedLength + " characters");
        }
        return Base64.getDecoder().decode(encoded);
    }
}
