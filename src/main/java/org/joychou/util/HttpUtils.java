package org.joychou.util;

import com.squareup.okhttp.OkHttpClient;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.fluent.Executor;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.apache.http.util.EntityUtils;
import org.jsoup.Connection;
import org.jsoup.Jsoup;
import org.joychou.security.ssrf.SSRFChecker;
import org.joychou.security.ssrf.SSRFException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.*;

/**
 * @author JoyChou 2020-04-06
 */
public class HttpUtils {

    private final static Logger logger = LoggerFactory.getLogger(HttpUtils.class);

    /** Maximum number of redirects that are followed. Every hop is validated again. */
    private static final int MAX_REDIRECTS = 5;
    private static final int TIMEOUT_MS = 6000;


    /**
     * Redirects are never followed by the http clients themselves. Each redirect target goes through
     * {@link SSRFChecker#assertSafeUrl(String)} before it is requested, so a public url can not
     * bounce the request to an internal address.
     */
    private static boolean isRedirect(int code) {
        return code == 301 || code == 302 || code == 303 || code == 307 || code == 308;
    }


    /**
     * Resolve the Location header against the url it came from.
     */
    private static String redirectTarget(String current, String location) throws IOException {
        if (location == null || location.isEmpty()) {
            throw new IOException("Redirect without Location header");
        }
        return new URL(new URL(current), location).toString();
    }


    /**
     * Open a connection to a validated http(s) url. Redirects are followed manually and every hop
     * is validated before it is requested.
     */
    private static HttpURLConnection openSafeConnection(String url) throws IOException {
        String current = url;
        for (int i = 0; i <= MAX_REDIRECTS; i++) {
            SSRFChecker.assertSafeUrl(current);
            HttpURLConnection conn = (HttpURLConnection) new URL(current).openConnection();
            conn.setInstanceFollowRedirects(false);
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            int code = conn.getResponseCode(); // send request
            if (!isRedirect(code)) {
                return conn;
            }
            String location = conn.getHeaderField("Location");
            conn.disconnect();
            current = redirectTarget(current, location);
        }
        throw new IOException("Too many redirects");
    }


    /**
     * Open a stream to a remote http(s) resource. The url and every redirect hop are validated.
     *
     * @throws IOException   if the request fails
     * @throws SSRFException if the url is illegal or points to an internal address
     */
    public static InputStream openStream(String url) throws IOException {
        return openSafeConnection(url).getInputStream(); // send request
    }


    private static RequestConfig noRedirectConfig() {
        return RequestConfig.custom().setRedirectsEnabled(false)
                .setConnectTimeout(TIMEOUT_MS).setSocketTimeout(TIMEOUT_MS).build();
    }


    private static String readAll(InputStream is) throws IOException {
        try (BufferedReader in = new BufferedReader(new InputStreamReader(is))) {
            String inputLine;
            StringBuilder html = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                html.append(inputLine);
            }
            return html.toString();
        }
    }


    public static String commonHttpClient(String url) {

        HttpClient client = new HttpClient();
        String current = url;

        try {
            for (int i = 0; i <= MAX_REDIRECTS; i++) {
                SSRFChecker.assertSafeUrl(current);
                GetMethod method = new GetMethod(current);
                method.setFollowRedirects(false);
                try {
                    int code = client.executeMethod(method); // send request
                    if (isRedirect(code)) {
                        org.apache.commons.httpclient.Header location = method.getResponseHeader("Location");
                        current = redirectTarget(current, location == null ? null : location.getValue());
                        continue;
                    }
                    byte[] resBody = method.getResponseBody();
                    return new String(resBody);
                } finally {
                    // Release the connection.
                    method.releaseConnection();
                }
            }
            return "Error: Too many redirects";
        } catch (IOException | SSRFException e) {
            return "Error: " + e.getMessage();
        }
    }


    public static String request(String url) {
        try {
            Executor executor = Executor.newInstance(HttpClients.custom().disableRedirectHandling().build());
            String current = url;
            for (int i = 0; i <= MAX_REDIRECTS; i++) {
                SSRFChecker.assertSafeUrl(current);
                HttpResponse response = executor.execute(Request.Get(current)
                        .connectTimeout(TIMEOUT_MS).socketTimeout(TIMEOUT_MS)).returnResponse();
                int code = response.getStatusLine().getStatusCode();
                if (isRedirect(code)) {
                    Header location = response.getFirstHeader("Location");
                    current = redirectTarget(current, location == null ? null : location.getValue());
                    continue;
                }
                return EntityUtils.toString(response.getEntity());
            }
            return "Too many redirects";
        } catch (Exception e) {
            return e.getMessage();
        }
    }


    public static String httpClient(String url) {

        try (CloseableHttpClient client = HttpClients.custom().disableRedirectHandling().build()) {
            String current = url;
            for (int i = 0; i <= MAX_REDIRECTS; i++) {
                SSRFChecker.assertSafeUrl(current);
                HttpGet httpGet = new HttpGet(current);
                httpGet.setConfig(noRedirectConfig());
                try (CloseableHttpResponse httpResponse = client.execute(httpGet)) { // send request
                    int code = httpResponse.getStatusLine().getStatusCode();
                    if (isRedirect(code)) {
                        Header location = httpResponse.getFirstHeader("Location");
                        current = redirectTarget(current, location == null ? null : location.getValue());
                        continue;
                    }
                    return readAll(httpResponse.getEntity().getContent());
                }
            }
            return "Too many redirects";
        } catch (Exception e) {
            return e.getMessage();
        }
    }


    public static String URLConnection(String url) {
        try {
            HttpURLConnection urlConnection = openSafeConnection(url); //send request
            return readAll(urlConnection.getInputStream());
        } catch (IOException | SSRFException e) {
            logger.error(e.getMessage());
            return e.getMessage();
        }
    }


    /**
     * Redirects are followed manually and every hop is validated.
     * UserAgent is Java/1.8.0_102.
     */
    public static String HttpURLConnection(String url) {
        try {
            // Many HttpURLConnection methods can send http request, such as getResponseCode, getHeaderField
            HttpURLConnection conn = openSafeConnection(url);  // send request
            return readAll(conn.getInputStream());
        } catch (IOException | SSRFException e) {
            logger.error(e.getMessage());
            return e.getMessage();
        }
    }


    /**
     * Jsoup is a HTML parser about Java.
     *
     * @param url http request url
     */
    public static String Jsoup(String url) {
        try {
            String current = url;
            for (int i = 0; i <= MAX_REDIRECTS; i++) {
                SSRFChecker.assertSafeUrl(current);
                Connection.Response res = Jsoup.connect(current)
                        .followRedirects(false)
                        .timeout(3000)
                        .cookie("name", "joychou") // request cookies
                        .execute();
                if (isRedirect(res.statusCode())) {
                    current = redirectTarget(current, res.header("Location"));
                    continue;
                }
                return res.parse().outerHtml();
            }
            return "Too many redirects";
        } catch (IOException | SSRFException e) {
            return e.getMessage();
        }
    }


    /**
     * Redirects are followed manually and every hop is validated.
     *
     * UserAgent is <code>okhttp/2.5.0</code>.
     */
    public static String okhttp(String url) throws IOException {
        OkHttpClient client = new OkHttpClient();
        client.setFollowRedirects(false);
        client.setFollowSslRedirects(false);
        String current = url;
        for (int i = 0; i <= MAX_REDIRECTS; i++) {
            try {
                SSRFChecker.assertSafeUrl(current);
            } catch (SSRFException e) {
                return e.getMessage();
            }
            com.squareup.okhttp.Request ok_http = new com.squareup.okhttp.Request.Builder().url(current).build();
            com.squareup.okhttp.Response res = client.newCall(ok_http).execute();
            if (isRedirect(res.code())) {
                String location = res.header("Location");
                res.body().close();
                current = redirectTarget(current, location);
                continue;
            }
            return res.body().string();
        }
        return "Too many redirects";
    }


    /**
     * Redirects are followed manually and every hop is validated.
     *
     * UserAgent is Java/1.8.0_102.
     *
     * @param url http request url
     */
    public static void imageIO(String url) {
        try {
            URL u = new URL(url);
            // Only remote http(s) resources; reject file:, jar: etc. which read local files.
            String protocol = u.getProtocol();
            if (!"http".equalsIgnoreCase(protocol) && !"https".equalsIgnoreCase(protocol)) {
                logger.error("Illegal url protocol: {}", protocol);
                return;
            }
            HttpURLConnection conn = openSafeConnection(url); // send request
            try (InputStream is = conn.getInputStream()) {
                ImageIO.read(is);
            }
        } catch (IOException | SSRFException e) {
            logger.error(e.getMessage());
        }

    }


    /**
     * IOUtils which is wrapped by URLConnection can get remote pictures.
     * Redirects are followed manually and every hop is validated.
     *
     * @param url http request url
     */
    public static void IOUtils(String url) {
        try {
            HttpURLConnection conn = openSafeConnection(url); // send request
            try (InputStream is = conn.getInputStream()) {
                IOUtils.toByteArray(is);
            }
        } catch (IOException | SSRFException e) {
            logger.error(e.getMessage());
        }
    }


    public static String HttpAsyncClients(String url) {
        CloseableHttpAsyncClient httpclient = HttpAsyncClients.createDefault();
        try {
            httpclient.start();
            String current = url;
            for (int i = 0; i <= MAX_REDIRECTS; i++) {
                SSRFChecker.assertSafeUrl(current);
                final HttpGet request = new HttpGet(current);
                request.setConfig(noRedirectConfig());
                Future<HttpResponse> future = httpclient.execute(request, null);
                HttpResponse response = future.get(6000, TimeUnit.MILLISECONDS);
                int code = response.getStatusLine().getStatusCode();
                if (isRedirect(code)) {
                    Header location = response.getFirstHeader("Location");
                    current = redirectTarget(current, location == null ? null : location.getValue());
                    continue;
                }
                return EntityUtils.toString(response.getEntity());
            }
            return "Too many redirects";
        } catch (Exception e) {
            return e.getMessage();
        } finally {
            try {
                httpclient.close();
            } catch (Exception e) {
                logger.error(e.getMessage());
            }
        }
    }
}
