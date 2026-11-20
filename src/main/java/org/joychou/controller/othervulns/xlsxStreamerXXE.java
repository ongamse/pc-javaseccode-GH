package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.ss.usermodel.Workbook;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
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
        rejectDoctypeInXmlParts(content);
        StreamingReader.builder().open(new ByteArrayInputStream(content));
    }

    /**
     * xlsx-streamer 2.0.0 parses the XML parts with a DTD-enabled parser. Reject any part
     * of the package that declares a DOCTYPE (or is not well-formed) before it reaches the library.
     */
    private static void rejectDoctypeInXmlParts(byte[] content) throws IOException {
        try {
            SAXParserFactory spf = SAXParserFactory.newInstance();
            spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            SAXParser parser = spf.newSAXParser();

            try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(content))) {
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    String name = entry.getName().toLowerCase();
                    if (entry.isDirectory() || !(name.endsWith(".xml") || name.endsWith(".rels"))) {
                        continue;
                    }
                    ByteArrayOutputStream bos = new ByteArrayOutputStream();
                    byte[] buf = new byte[8192];
                    int n;
                    while ((n = zis.read(buf)) > 0) {
                        bos.write(buf, 0, n);
                    }
                    parser.reset();
                    parser.parse(new InputSource(new ByteArrayInputStream(bos.toByteArray())), new DefaultHandler());
                }
            }
        } catch (ParserConfigurationException | SAXException e) {
            throw new IOException("Invalid or unsafe XML in uploaded xlsx", e);
        }
    }


    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
