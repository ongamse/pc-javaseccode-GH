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
import org.joychou.security.SecurityUtil;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.concurrent.*;

/**
 * @author JoyChou 2020-04-06
 */
public class HttpUtils {

    private final static Logger logger = LoggerFactory.getLogger(HttpUtils.class);
    private static final String ILLEGAL_URL = "Illegal url";

    /**
     * Only allow http(s) urls whose host resolves to a non-internal address
     * (see ssrf_safe_domain.xml blockips). Fails closed on any parsing/resolution error.
     * Callers must also disable redirect following, otherwise the redirect target is not checked.
     */
    private static boolean isSafeUrl(String url) {
        try {
            return url != null && SecurityUtil.isHttp(url) && SecurityUtil.checkSSRFWithoutRedirect(url);
        } catch (Exception e) {
            logger.error("SSRF check failed: {}", e.toString());
            return false;
        }
    }

    public static String commonHttpClient(String url) {

        if (!isSafeUrl(url)) {
            return "Error: " + ILLEGAL_URL;
        }

        HttpClient client = new HttpClient();
        GetMethod method = new GetMethod(url);
        method.setFollowRedirects(false);

        try {
            client.executeMethod(method); // send request
            byte[] resBody = method.getResponseBody();
            return new String(resBody);

        } catch (IOException e) {
            return "Error: " + e.getMessage();
        } finally {
            // Release the connection.
            method.releaseConnection();
        }
    }


    public static String request(String url) {
        if (!isSafeUrl(url)) {
            return ILLEGAL_URL;
        }
        try {
            // redirects are not followed, so the checked host is the only host contacted
            Executor executor = Executor.newInstance(HttpClients.custom().disableRedirectHandling().build());
            return executor.execute(Request.Get(url)).returnContent().toString();
        } catch (Exception e) {
            return e.getMessage();
        }
    }


    public static String httpClient(String url) {

        if (!isSafeUrl(url)) {
            return ILLEGAL_URL;
        }

        StringBuilder result = new StringBuilder();

        try {

            CloseableHttpClient client = HttpClients.createDefault();
            HttpGet httpGet = new HttpGet(url);
            // set redirect enable false
            httpGet.setConfig(RequestConfig.custom().setRedirectsEnabled(false).build());
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
        if (!isSafeUrl(url)) {
            return ILLEGAL_URL;
        }
        try {
            URL u = new URL(url);
            URLConnection urlConnection = u.openConnection();
            ((HttpURLConnection) urlConnection).setInstanceFollowRedirects(false);
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
        if (!isSafeUrl(url)) {
            return ILLEGAL_URL;
        }
        try {
            URL u = new URL(url);
            URLConnection urlConnection = u.openConnection();
            HttpURLConnection conn = (HttpURLConnection) urlConnection;
            conn.setInstanceFollowRedirects(false);
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
        if (!isSafeUrl(url)) {
            return ILLEGAL_URL;
        }
        try {
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
        if (!isSafeUrl(url)) {
            return ILLEGAL_URL;
        }
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
        // Only remote http(s) resources on non-internal hosts; reject file:/jar: etc.
        if (!isSafeUrl(url)) {
            logger.error("Illegal url: {}", url);
            return;
        }
        try {
            URL u = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) u.openConnection();
            conn.setInstanceFollowRedirects(false);
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
        if (!isSafeUrl(url)) {
            logger.error("Illegal url: {}", url);
            return;
        }
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setInstanceFollowRedirects(false);
            IOUtils.toByteArray(conn);
        } catch (IOException e) {
            logger.error(e.getMessage());
        }
    }


    public static String HttpAsyncClients(String url) {
        if (!isSafeUrl(url)) {
            return ILLEGAL_URL;
        }
        CloseableHttpAsyncClient httpclient = HttpAsyncClients.createDefault();
        try {
            httpclient.start();
            final HttpGet request = new HttpGet(url);
            request.setConfig(RequestConfig.custom().setRedirectsEnabled(false).build());
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
