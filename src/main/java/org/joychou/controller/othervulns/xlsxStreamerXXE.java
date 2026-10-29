package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.ss.usermodel.Workbook;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;
import org.xml.sax.InputSource;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;


/**
 * Desc:  xlsx-streamer xxe vuln code
 * Usage: xl/workbook.xml
 * Ref:   https://www.itread01.com/hkpcyyp.html
 * Fix:   update xlsx-streamer to 2.1.0 or above
 *
 * @author JoyChou @2019-09-05
 */
@Controller
@RequestMapping("xlsx-streamer")
public class xlsxStreamerXXE {


    @GetMapping("/upload")
    public String index() {
        return "xxe_upload"; // return xxe_upload.html page
    }


    @PostMapping("/readxlsx")
    public void xllx_streamer_xxe(MultipartFile file) throws IOException {
        byte[] content = file.getBytes();
        rejectXmlWithDoctype(content);
        StreamingReader.builder().open(new ByteArrayInputStream(content));
    }


    /**
     * Parse every XML part of the xlsx package with a hardened SAX parser (DOCTYPE and
     * external entities disallowed) so that crafted parts such as xl/workbook.xml are
     * rejected before the vulnerable streaming reader processes them.
     */
    private static void rejectXmlWithDoctype(byte[] content) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(content))) {
            SAXParserFactory spf = SAXParserFactory.newInstance();
            spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            spf.setNamespaceAware(true);

            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName().toLowerCase();
                if (entry.isDirectory() || !(name.endsWith(".xml") || name.endsWith(".rels"))) {
                    continue;
                }
                SAXParser parser = spf.newSAXParser();
                // Do not let the parser close the shared zip stream.
                InputStream entryStream = new java.io.FilterInputStream(zis) {
                    @Override
                    public void close() {
                        // keep underlying ZipInputStream open
                    }
                };
                parser.parse(new InputSource(entryStream), new DefaultHandler());
            }
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Rejected xlsx: unsafe or malformed XML content", e);
        }
    }


    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
