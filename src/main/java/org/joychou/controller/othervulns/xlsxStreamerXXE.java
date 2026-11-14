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
import javax.xml.parsers.SAXParserFactory;
import java.io.FileInputStream;
import java.io.FilterInputStream;
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
        // Reject packages whose XML parts declare a DOCTYPE / entities before xlsx-streamer parses them.
        try (InputStream in = file.getInputStream()) {
            rejectDoctypeInXmlParts(in);
        }
        StreamingReader.builder().open(file.getInputStream());
    }


    /**
     * Stream through every XML part of the OOXML (zip) package with a hardened SAX parser
     * (DOCTYPE and external entities disabled). Throws IOException if any part is unsafe or malformed.
     */
    private static void rejectDoctypeInXmlParts(InputStream in) throws IOException {
        try {
            SAXParserFactory spf = SAXParserFactory.newInstance();
            spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            spf.setNamespaceAware(true);

            ZipInputStream zis = new ZipInputStream(in);
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName().toLowerCase();
                if (entry.isDirectory() || !(name.endsWith(".xml") || name.endsWith(".rels"))) {
                    continue;
                }
                // Do not let the parser close the shared zip stream.
                InputStream partStream = new FilterInputStream(zis) {
                    @Override
                    public void close() {
                        // keep zip stream open
                    }
                };
                spf.newSAXParser().parse(new InputSource(partStream), new DefaultHandler());
            }
        } catch (ParserConfigurationException | SAXException e) {
            throw new IOException("Rejected unsafe or malformed XML in xlsx package", e);
        }
    }


    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
