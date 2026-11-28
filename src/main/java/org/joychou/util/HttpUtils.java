package org.joychou.util;

import com.squareup.okhttp.OkHttpClient;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.fluent.Executor;
import org.apache.http.client.fluent.Request;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.apache.http.util.EntityUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.joychou.security.SecurityUtil;
import org.joychou.security.ssrf.SSRFChecker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.util.concurrent.*;

/**
 * @author JoyChou 2020-04-06
 */
public class HttpUtils {

    private final static Logger logger = LoggerFactory.getLogger(HttpUtils.class);

    private static final RequestConfig NO_REDIRECT_CONFIG = RequestConfig.custom().setRedirectsEnabled(false).build();


    /**
     * Shared SSRF guard for every outbound request in this class. The url must be http/https,
     * parse identically as {@link URI} and {@link URL}, and its host must only resolve to
     * public addresses (no loopback, link-local/metadata, private ranges).
     * Redirects are disabled by every sink below, so the validated destination is the only one contacted.
     *
     * @param url untrusted url
     * @throws IOException if the url is not allowed
     */
    public static void checkUrl(String url) throws IOException {
        if (url == null || !SecurityUtil.isHttp(url)) {
            throw new IOException("[-] SSRF check failed. Only http/https is allowed.");
        }
        try {
            String uriHost = new URI(url).getHost();
            String urlHost = new URL(url).getHost();
            if (uriHost == null || !uriHost.equalsIgnoreCase(urlHost)) {
                throw new IOException("[-] SSRF check failed. Ambiguous host.");
            }
        } catch (java.net.URISyntaxException e) {
            throw new IOException("[-] SSRF check failed. Illegal url.");
        }
        if (!SSRFChecker.isSafeUrl(url)) {
            throw new IOException("[-] SSRF check failed. Dangerous url.");
        }
    }


    /**
     * Validate the url and open an HttpURLConnection that does not follow redirects.
     *
     * @param url untrusted url
     * @return unconnected connection to the validated url
     * @throws IOException if the url is not allowed
     */
    public static HttpURLConnection openConnection(String url) throws IOException {
        checkUrl(url);
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setInstanceFollowRedirects(false);
        return conn;
    }


    public static String commonHttpClient(String url) {

        HttpClient client = new HttpClient();

        try {
            checkUrl(url);
            GetMethod method = new GetMethod(url);
            method.setFollowRedirects(false);
            return executeCommonHttpClient(client, method);
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
    }


    private static String executeCommonHttpClient(HttpClient client, GetMethod method) throws IOException {
        try {
            client.executeMethod(method); // send request
            byte[] resBody = method.getResponseBody();
            return new String(resBody);

        } finally {
            // Release the connection.
            method.releaseConnection();
        }
    }


    public static String request(String url) {
        try {
            checkUrl(url);
            Executor executor = Executor.newInstance(HttpClients.custom().disableRedirectHandling().build());
            return executor.execute(Request.Get(url)).returnContent().toString();
        } catch (Exception e) {
            return e.getMessage();
        }
    }


    public static String httpClient(String url) {

        StringBuilder result = new StringBuilder();

        try {

            checkUrl(url);
            CloseableHttpClient client = HttpClients.createDefault();
            HttpGet httpGet = new HttpGet(url);
            httpGet.setConfig(NO_REDIRECT_CONFIG);
            HttpResponse httpResponse = client.execute(httpGet); // send request
            BufferedReader rd = new BufferedReader(new InputStreamReader(httpResponse.getEntity().getContent()));

            String line;
            while ((line = rd.readLine()) != null) {
                result.append(line);
            }

            return result.toString();

        } catch (Exception e) {
            return e.getMessage();
        }
    }


    public static String URLConnection(String url) {
        try {
            URLConnection urlConnection = openConnection(url);
            BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream())); //send request
            String inputLine;
            StringBuilder html = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                html.append(inputLine);
            }
            in.close();
            return html.toString();
        } catch (Exception e) {
            logger.error(e.getMessage());
            return e.getMessage();
        }
    }


    /**
     * The default setting of followRedirects is true.
     * UserAgent is Java/1.8.0_102.
     */
    public static String HttpURLConnection(String url) {
        try {
            HttpURLConnection conn = openConnection(url);
//             Many HttpURLConnection methods can send http request, such as getResponseCode, getHeaderField
            InputStream is = conn.getInputStream();  // send request
            BufferedReader in = new BufferedReader(new InputStreamReader(is));
            String inputLine;
            StringBuilder html = new StringBuilder();

            while ((inputLine = in.readLine()) != null) {
                html.append(inputLine);
            }
            in.close();
            return html.toString();
        } catch (IOException e) {
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
            checkUrl(url);
            Document doc = Jsoup.connect(url)
                    .followRedirects(false)
                    .timeout(3000)
                    .cookie("name", "joychou") // request cookies
                    .execute().parse();
            return doc.outerHtml();
        } catch (IOException e) {
            return e.getMessage();
        }
    }


    /**
     * The default setting of followRedirects is true. The option of followRedirects is true.
     *
     * UserAgent is <code>okhttp/2.5.0</code>.
     */
    public static String okhttp(String url) throws IOException {
        checkUrl(url);
        OkHttpClient client = new OkHttpClient();
        client.setFollowRedirects(false);
        client.setFollowSslRedirects(false);
        com.squareup.okhttp.Request ok_http = new com.squareup.okhttp.Request.Builder().url(url).build();
        return client.newCall(ok_http).execute().body().string();
    }


    /**
     * The default setting of followRedirects is true.
     *
     * UserAgent is Java/1.8.0_102.
     *
     * @param url http request url
     */
    public static void imageIO(String url) {
        try {
            HttpURLConnection conn = openConnection(url);
            try (InputStream is = conn.getInputStream()) { // send request
                ImageIO.read(is);
            }
        } catch (IOException e) {
            logger.error(e.getMessage());
        }

    }


    /**
     * IOUtils which is wrapped by URLConnection can get remote pictures.
     * The default setting of redirection is true.
     *
     * @param url http request url
     */
    public static void IOUtils(String url) {
        try {
            HttpURLConnection conn = openConnection(url);
            try (InputStream is = conn.getInputStream()) { // send request
                IOUtils.toByteArray(is);
            }
        } catch (IOException e) {
            logger.error(e.getMessage());
        }
    }


    public static String HttpAsyncClients(String url) {
        CloseableHttpAsyncClient httpclient = HttpAsyncClients.createDefault();
        try {
            checkUrl(url);
            httpclient.start();
            final HttpGet request = new HttpGet(url);
            request.setConfig(NO_REDIRECT_CONFIG);
            Future<HttpResponse> future = httpclient.execute(request, null);
            HttpResponse response = future.get(6000, TimeUnit.MILLISECONDS);
            return EntityUtils.toString(response.getEntity());
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
