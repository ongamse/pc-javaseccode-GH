package org.joychou.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.util.regex.Pattern;

import com.google.common.base.Preconditions;
import org.springframework.web.util.HtmlUtils;

public class WebUtils {

    // Get request body.
    public static String getRequestBody(HttpServletRequest request) throws IOException {
        InputStream in = request.getInputStream();
        return convertStreamToString(in);
    }

    // https://stackoverflow.com/questions/309424/how-do-i-read-convert-an-inputstream-into-a-string-in-java
    public static String convertStreamToString(java.io.InputStream is) {
        java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";
    }

    public static String getCookieValueByName(HttpServletRequest request, String cookieName) {
        Cookie cookie = org.springframework.web.util.WebUtils.getCookie(request, cookieName);
        return cookie == null ? null : cookie.getValue();
    }


    // Strict JSONP callback: JavaScript identifier(s) separated by dots, no other characters.
    private static final Pattern JSONP_CALLBACK = Pattern.compile("^[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*){0,4}$");

    /**
     * Check a JSONP callback name against a strict identifier allowlist.
     */
    public static boolean isValidJsonpCallback(String callback) {
        return callback != null && callback.length() <= 64 && JSONP_CALLBACK.matcher(callback).matches();
    }

    /**
     * HTML-escape untrusted text before it is written into a response body.
     * Null-safe: null stays null.
     */
    public static String escapeHtml(String input) {
        return input == null ? null : HtmlUtils.htmlEscape(input);
    }

    /**
     * Remove CR, LF and all other ISO control characters from an untrusted value before it is
     * written into an HTTP response header (prevents header injection / response splitting).
     * Null-safe: null stays null.
     */
    public static String sanitizeHeaderValue(String value) {
        if (value == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char ch = value.charAt(i);
            if (!Character.isISOControl(ch)) {
                sb.append(ch);
            }
        }
        return sb.toString();
    }

    public static String json2Jsonp(String callback, String jsonStr) {
        if (!isValidJsonpCallback(callback)) {
            return "error";
        }
        return callback + "(" + jsonStr + ")";
    }


    public static String getFileExtension(String fullName) {
        Preconditions.checkNotNull(fullName);
        String fileName = (new File(fullName)).getName();
        int dotIndex = fileName.lastIndexOf('.');
        return dotIndex == -1 ? "" : fileName.substring(dotIndex + 1);
    }


    public static String getNameWithoutExtension(String file) {
        Preconditions.checkNotNull(file);
        String fileName = (new File(file)).getName();
        int dotIndex = fileName.lastIndexOf('.');
        return dotIndex == -1 ? fileName : fileName.substring(0, dotIndex);
    }


}
