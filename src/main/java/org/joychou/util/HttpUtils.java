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
import org.joychou.security.ssrf.SSRFChecker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.imageio.ImageIO;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.util.concurrent.*;

/**
 * @author JoyChou 2020-04-06
 */
public class HttpUtils {

    private final static Logger logger = LoggerFactory.getLogger(HttpUtils.class);

    /**
     * Shared SSRF validation for every outbound fetch in this class.
     * Only http/https is allowed, the host must be a well-formed URI host, and every address
     * the host resolves to must be public (not loopback, link-local/metadata, private, CGNAT,
     * multicast or in the configured SSRFChecker block list).
     *
     * @param url untrusted url
     * @return the parsed, validated URL
     * @throws IOException if the url is not an allowed outbound target
     */
    public static URL requireSafeUrl(String url) throws IOException {
        if (url == null) {
            throw new IOException("Illegal url");
        }
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw new IOException("Illegal url");
        }
        String scheme = uri.getScheme();
        if (scheme == null || !("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))) {
            throw new IOException("Illegal protocol");
        }
        String host = uri.getHost();
        if (host == null || host.isEmpty()) {
            throw new IOException("Illegal host");
        }
        URL u = new URL(url);
        // URI and URL must agree on the host, otherwise parser differences can be abused.
        if (!host.equalsIgnoreCase(u.getHost())) {
            throw new IOException("Illegal host");
        }
        // Repo's own configurable internal-ip check (also handles octal ip forms).
        if (SSRFChecker.isInternalIpByUrl(url)) {
            throw new IOException("Illegal host");
        }
        try {
            for (InetAddress addr : InetAddress.getAllByName(host)) {
                if (isBlockedAddress(addr)) {
                    throw new IOException("Illegal host");
                }
            }
        } catch (UnknownHostException e) {
            throw new IOException("Illegal host");
        }
        return u;
    }

    private static boolean isBlockedAddress(InetAddress addr) {
        if (addr.isAnyLocalAddress() || addr.isLoopbackAddress() || addr.isLinkLocalAddress()
                || addr.isSiteLocalAddress() || addr.isMulticastAddress()) {
            return true;
        }
        byte[] b = addr.getAddress();
        if (b.length == 4) {
            int first = b[0] & 0xff;
            int second = b[1] & 0xff;
            // 0.0.0.0/8 and 100.64.0.0/10 (carrier-grade NAT)
            return first == 0 || (first == 100 && second >= 64 && second <= 127);
        }
        // IPv6 unique local fc00::/7
        return (b[0] & 0xfe) == 0xfc;
    }

    /**
     * Open a connection to a validated url. Redirects are not followed, so a validated host
     * cannot bounce the request to an internal target.
     */
    private static URLConnection openValidatedConnection(String url) throws IOException {
        URLConnection connection = requireSafeUrl(url).openConnection();
        if (connection instanceof HttpURLConnection) {
            ((HttpURLConnection) connection).setInstanceFollowRedirects(false);
        }
        return connection;
    }

    /**
     * Open an input stream for a validated http(s) url without following redirects.
     */
    public static InputStream openStream(String url) throws IOException {
        return openValidatedConnection(url).getInputStream(); // send request
    }

    public static String commonHttpClient(String url) {

        HttpClient client = new HttpClient();
        GetMethod method;
        try {
            method = new GetMethod(requireSafeUrl(url).toExternalForm());
        } catch (IOException e) {
            return "Error: " + e.getMessage();
        }
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
        try {
            requireSafeUrl(url);
            Executor executor = Executor.newInstance(HttpClients.custom().disableRedirectHandling().build());
            return executor.execute(Request.Get(url)).returnContent().toString();
        } catch (Exception e) {
            return e.getMessage();
        }
    }


    public static String httpClient(String url) {

        StringBuilder result = new StringBuilder();

        try {

            requireSafeUrl(url);
            CloseableHttpClient client = HttpClients.createDefault();
            HttpGet httpGet = new HttpGet(url);
            // redirects disabled so a validated host cannot bounce to an internal target
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
        try {
            URLConnection urlConnection = openValidatedConnection(url);
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
            URLConnection urlConnection = openValidatedConnection(url);
            HttpURLConnection conn = (HttpURLConnection) urlConnection;
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
            requireSafeUrl(url);
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
        requireSafeUrl(url);
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
        try (InputStream in = openValidatedConnection(url).getInputStream()) { // send request
            ImageIO.read(in);
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
            IOUtils.toByteArray(openValidatedConnection(url));
        } catch (IOException e) {
            logger.error(e.getMessage());
        }
    }


    public static String HttpAsyncClients(String url) {
        try {
            requireSafeUrl(url);
        } catch (IOException e) {
            return e.getMessage();
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
