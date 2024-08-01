package org.joychou.controller;

import cn.hutool.http.HttpUtil;
import org.joychou.security.SecurityUtil;
import org.joychou.security.ssrf.SSRFException;
import org.joychou.service.HttpService;
import org.joychou.util.HttpUtils;
import org.joychou.util.WebUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.*;


/**
 * Java SSRF vuln or security code.
 *
 * @author JoyChou @2017-12-28
 */

@RestController
@RequestMapping("/ssrf")
public class SSRF {

    private static final Logger logger = LoggerFactory.getLogger(SSRF.class);

    @Resource
    private HttpService httpService;

    /**
     * <p>
     *    The default setting of followRedirects is true. <br>
     *    Protocol: file ftp mailto http https jar netdoc. <br>
     *    UserAgent is Java/1.8.0_102.
     * </p>
     * <a href="http://localhost:8080/ssrf/urlConnection/vuln?url=file:///etc/passwd">http://localhost:8080/ssrf/urlConnection/vuln?url=file:///etc/passwd</a>
     */
    @RequestMapping(value = "/urlConnection/vuln", method = {RequestMethod.POST, RequestMethod.GET})
    public String URLConnectionVuln(String url) {
        return HttpUtils.URLConnection(url);
    }


    @GetMapping("/urlConnection/sec")
    public String URLConnectionSec(String url) {

        // Decline not http/https protocol
        if (!SecurityUtil.isHttp(url)) {
            return "[-] SSRF check failed";
        }

        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.URLConnection(url);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
        } finally {
            SecurityUtil.stopSSRFHook();
        }

    }


    /**
     * The default setting of followRedirects is true.
     * UserAgent is Java/1.8.0_102.
     */
    @GetMapping("/HttpURLConnection/sec")
    public String httpURLConnection(@RequestParam String url) {
        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.HttpURLConnection(url);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
        } finally {
            SecurityUtil.stopSSRFHook();
        }
    }


    @GetMapping("/HttpURLConnection/vuln")
    public String httpURLConnectionVuln(@RequestParam String url) {
        return HttpUtils.HttpURLConnection(url);
    }

    /**
     * The default setting of followRedirects is true.
     * UserAgent is <code>Apache-HttpClient/4.5.12 (Java/1.8.0_102)</code>. <br>
     * <a href="http://localhost:8080/ssrf/request/sec?url=http://test.joychou.org">http://localhost:8080/ssrf/request/sec?url=http://test.joychou.org</a>
     */
    @GetMapping("/request/sec")
    public String request(@RequestParam String url) {
        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.request(url);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
        } finally {
            SecurityUtil.stopSSRFHook();
        }
    }


    /**
     * Download the url file. <br>
     * <code>new URL(String url).openConnection()</code>  <br>
     * <code>new URL(String url).openStream()</code> <br>
     * <code>new URL(String url).getContent()</code> <br>
     * <a href="http://localhost:8080/ssrf/openStream?url=file:///etc/passwd">http://localhost:8080/ssrf/openStream?url=file:///etc/passwd</a>

     */
	@GetMapping("/openStream")
    public void openStream(@RequestParam String url, HttpServletResponse response) throws IOException {
        InputStream inputStream = null;
        OutputStream outputStream = null;
        try {
            // Validate the URL before processing
            URL u = new URL(url);
            String fileName = u.getFile();
            String downLoadImgFileName = FilenameUtils.getName(fileName);
            
            // Set the content-disposition header with a safe filename
            response.setHeader("content-disposition", "attachment;filename=\"" + downLoadImgFileName + "\"");

            inputStream = u.openStream();
            outputStream = response.getOutputStream();
            byte[] buffer = new byte[1024];
            int length;
            while ((length = inputStream.read(buffer)) > 0) {
                outputStream.write(buffer, 0, length);
            }
        } catch (MalformedURLException e) {
            // Handle invalid URLs
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid URL: " + url);
        } catch (IOException e) {
            // Handle IO errors
            logger.error("Error downloading file: ", e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error downloading file");
        } finally {
            // Ensure resources are closed
            if (inputStream != null) {
                inputStream.close();
            }
            if (outputStream != null) {
                outputStream.close();
            }
        }
    }


        } catch (MalformedURLException e) {
            logger.error("Invalid URL: " + e.toString());
        } catch (IOException e) {
            logger.error("I/O error: " + e.toString());
        } finally {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    logger.error("Error closing input stream: " + e.toString());
                }
            }
            if (outputStream != null) {
                try {
                    outputStream.close();
                } catch (IOException e) {
                    logger.error("Error closing output stream: " + e.toString());
                }
            }
        }
    }


        } catch (Exception e) {
            logger.error(e.toString());
        } finally {
            if (inputStream != null) {
                inputStream.close();
            }
            if (outputStream != null) {
                outputStream.close();
            }
        }
    }


    /**
     * The default setting of followRedirects is true.
     * UserAgent is Java/1.8.0_102.
     */
    @GetMapping("/ImageIO/sec")
    public String ImageIO(@RequestParam String url) {
        try {
            SecurityUtil.startSSRFHook();
            HttpUtils.imageIO(url);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
        } finally {
            SecurityUtil.stopSSRFHook();
        }

        return "ImageIO ssrf test";
    }


    @GetMapping("/okhttp/sec")
    public String okhttp(@RequestParam String url) {

        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.okhttp(url);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
        } finally {
            SecurityUtil.stopSSRFHook();
        }

    }

    /**
     * The default setting of followRedirects is true.
     * UserAgent is <code>Apache-HttpClient/4.5.12 (Java/1.8.0_102)</code>. <br>
     * <a href="http://localhost:8080/ssrf/httpclient/sec?url=http://www.baidu.com">http://localhost:8080/ssrf/httpclient/sec?url=http://www.baidu.com</a>
     */
    @GetMapping("/httpclient/sec")
    public String HttpClient(@RequestParam String url) {

        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.httpClient(url);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
        } finally {
            SecurityUtil.stopSSRFHook();
        }

    }


    /**
     * The default setting of followRedirects is true.
     * UserAgent is <code>Jakarta Commons-HttpClient/3.1</code>.
     * <a href="http://localhost:8080/ssrf/commonsHttpClient/sec?url=http://www.baidu.com">http://localhost:8080/ssrf/commonsHttpClient/sec?url=http://www.baidu.com</a>
     */
    @GetMapping("/commonsHttpClient/sec")
    public String commonsHttpClient(@RequestParam String url) {

        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.commonHttpClient(url);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
        } finally {
            SecurityUtil.stopSSRFHook();
        }

    }

    /**
     * The default setting of followRedirects is true.
     * UserAgent is the useragent of browser.<br>
     * <a href="http://localhost:8080/ssrf/Jsoup?url=http://www.baidu.com">http://localhost:8080/ssrf/Jsoup?url=http://www.baidu.com</a>
     */
    @GetMapping("/Jsoup/sec")
    public String Jsoup(@RequestParam String url) {

        try {
            SecurityUtil.startSSRFHook();
            return HttpUtils.Jsoup(url);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
        } finally {
            SecurityUtil.stopSSRFHook();
        }

    }


    /**
     * The default setting of followRedirects is true.
     * UserAgent is <code>Java/1.8.0_102</code>. <br>
     * <a href="http://localhost:8080/ssrf/IOUtils/sec?url=http://www.baidu.com">http://localhost:8080/ssrf/IOUtils/sec?url=http://www.baidu.com</a>
     */
    @GetMapping("/IOUtils/sec")
    public String IOUtils(String url) {
        try {
            SecurityUtil.startSSRFHook();
            HttpUtils.IOUtils(url);
        } catch (SSRFException | IOException e) {
            return e.getMessage();
        } finally {
            SecurityUtil.stopSSRFHook();
        }

        return "IOUtils ssrf test";
    }


    /**
     * The default setting of followRedirects is true.
     * UserAgent is <code>Apache-HttpAsyncClient/4.1.4 (Java/1.8.0_102)</code>.
     */
    @GetMapping("/HttpSyncClients/vuln")
    public String HttpSyncClients(@RequestParam("url") String url) {
        return HttpUtils.HttpAsyncClients(url);
    }


    /**
     * Only support HTTP protocol. <br>
     * GET HttpMethod follow redirects by default, other HttpMethods do not follow redirects. <br>
     * User-Agent is Java/1.8.0_102. <br>
     * <a href="http://127.0.0.1:8080/ssrf/restTemplate/vuln1?url=http://www.baidu.com">http://127.0.0.1:8080/ssrf/restTemplate/vuln1?url=http://www.baidu.com</a>
     */
    @GetMapping("/restTemplate/vuln1")
    public String RestTemplateUrlBanRedirects(String url){
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON_UTF8);
        return httpService.RequestHttpBanRedirects(url, headers);
    }


    @GetMapping("/restTemplate/vuln2")
    public String RestTemplateUrl(String url){
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON_UTF8);
        return httpService.RequestHttp(url, headers);
    }


    /**
     * UserAgent is Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36 Hutool.
     * Do not follow redirects. <br>
     * <a href="http://127.0.0.1:8080/ssrf/hutool/vuln?url=http://www.baidu.com">http://127.0.0.1:8080/ssrf/hutool/vuln?url=http://www.baidu.com</a>
     */
    @GetMapping("/hutool/vuln")
    public String hutoolHttp(String url){
        return HttpUtil.get(url);
    }


    /**
     * DnsRebind SSRF in java by setting ttl is zero. <br>
     * <a href="http://localhost:8080/ssrf/dnsrebind/vuln?url=http://test.joychou.org">http://localhost:8080/ssrf/dnsrebind/vuln?url=dnsrebind_url</a>
     */
    @GetMapping("/dnsrebind/vuln")
    public String DnsRebind(String url) {
        java.security.Security.setProperty("networkaddress.cache.negative.ttl" , "0");
        if (!SecurityUtil.checkSSRFWithoutRedirect(url)) {
            return "Dangerous url";
        }
        return HttpUtil.get(url);
    }


}


