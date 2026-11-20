package org.joychou.util;

import java.util.Base64;
import java.util.regex.Pattern;

/**
 * Guarded Base64 decoding for untrusted input. Bounds the length and checks
 * the character set before the JDK decoder runs, so oversized or malformed
 * data never reaches Base64.Decoder (Java4Shell hardening).
 */
public final class Base64Utils {

    /** Upper bound (chars) for untrusted Base64 input. */
    public static final int MAX_INPUT_LENGTH = 8192;

    /** Upper bound (chars) for untrusted compact JWT input. */
    public static final int MAX_JWT_LENGTH = 8192;

    private static final Pattern BASE64_PATTERN = Pattern.compile("^[A-Za-z0-9+/]*={0,2}$");
    private static final Pattern JWT_PATTERN =
            Pattern.compile("^[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*$");

    private Base64Utils() {
    }

    /**
     * Decode standard Base64 after validating length and charset.
     *
     * @param input untrusted Base64 string
     * @return decoded bytes
     * @throws IllegalArgumentException if input is null, too long, or not valid Base64
     */
    public static byte[] decodeUntrusted(String input) {
        if (input == null) {
            throw new IllegalArgumentException("Base64 input is null");
        }
        if (input.length() > MAX_INPUT_LENGTH) {
            throw new IllegalArgumentException("Base64 input too long");
        }
        if (!BASE64_PATTERN.matcher(input).matches()) {
            throw new IllegalArgumentException("Illegal base64 character");
        }
        return Base64.getDecoder().decode(input);
    }

    /**
     * Check that a compact JWT is bounded and made only of base64url segments
     * before a JWT library decodes it.
     */
    public static boolean isWellFormedJwt(String token) {
        return token != null
                && token.length() <= MAX_JWT_LENGTH
                && JWT_PATTERN.matcher(token).matches();
    }
}
