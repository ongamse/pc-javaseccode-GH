package org.joychou.util;

import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Strict, length-bounded Base64 decoding for untrusted input.
 */
public final class SafeBase64 {

    private static final Pattern STANDARD_BASE64 = Pattern.compile("^[A-Za-z0-9+/]*={0,2}$");

    private SafeBase64() {
    }

    /**
     * Decode untrusted standard Base64 text after validating its length and alphabet.
     *
     * @param encoded   untrusted Base64 text
     * @param maxLength maximum accepted length of the encoded text
     * @return decoded bytes
     * @throws IllegalArgumentException if the input is null, too long or not valid Base64
     */
    public static byte[] decode(String encoded, int maxLength) {
        if (encoded == null || encoded.isEmpty()) {
            throw new IllegalArgumentException("Base64 input is empty");
        }
        if (encoded.length() > maxLength) {
            throw new IllegalArgumentException("Base64 input is too long");
        }
        if (!STANDARD_BASE64.matcher(encoded).matches()) {
            throw new IllegalArgumentException("Base64 input contains illegal characters");
        }
        return Base64.getDecoder().decode(encoded);
    }
}
