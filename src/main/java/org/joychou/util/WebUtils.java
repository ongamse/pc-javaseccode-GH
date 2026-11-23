package org.joychou.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.util.regex.Pattern;

import com.google.common.base.Preconditions;

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


    // A JSONP callback must be a plain JS identifier path (e.g. "cb" or "ns.cb"); nothing else may reach the script.
    private static final Pattern SAFE_JSONP_CALLBACK =
            Pattern.compile("^[A-Za-z_$][A-Za-z0-9_$]*(\\.[A-Za-z_$][A-Za-z0-9_$]*)*$");
    private static final int MAX_JSONP_CALLBACK_LENGTH = 64;

    /**
     * Validate a user supplied JSONP callback name.
     *
     * @return the callback when it is a safe JS identifier path, otherwise null
     */
    public static String safeJsonpCallback(String callback) {
        if (callback == null || callback.length() > MAX_JSONP_CALLBACK_LENGTH
                || !SAFE_JSONP_CALLBACK.matcher(callback).matches()) {
            return null;
        }
        return callback;
    }

    public static String json2Jsonp(String callback, String jsonStr) {
        String safeCallback = safeJsonpCallback(callback);
        if (safeCallback == null) {
            return "error";
        }
        return safeCallback + "(" + jsonStr + ")";
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
