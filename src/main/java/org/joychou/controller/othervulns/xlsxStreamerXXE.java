package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.ss.usermodel.Workbook;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import javax.xml.parsers.SAXParserFactory;
import javax.xml.parsers.SAXParser;
import org.xml.sax.InputSource;
import org.xml.sax.helpers.DefaultHandler;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;


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
        // Save to a temp file so we can pre-validate XML entries for XXE
        File tempFile = Files.createTempFile("upload-", ".xlsx").toFile();
        try {
            file.transferTo(tempFile);
            validateNoXXE(tempFile);
            try (InputStream fis = new FileInputStream(tempFile)) {
                StreamingReader.builder().open(fis);
            }
        } catch (Exception e) {
            throw new IOException("XLSX validation failed: " + e.getMessage(), e);
        } finally {
            tempFile.delete();
        }
    }

    /**
     * Pre-validate XML entries inside the XLSX (ZIP) to reject external entities and DTDs.
     */
    private static void validateNoXXE(File xlsxFile) throws Exception {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        SAXParser parser = spf.newSAXParser();

        try (ZipFile zip = new ZipFile(xlsxFile)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.getName().endsWith(".xml") || entry.getName().endsWith(".rels")) {
                    try (InputStream is = zip.getInputStream(entry)) {
                        parser.parse(new InputSource(is), new DefaultHandler());
                    }
                }
            }
        }
    }


    public static void main(String[] args) throws Exception {
        File f = new File("poc.xlsx");
        validateNoXXE(f);
        StreamingReader.builder().open(new FileInputStream(f));
    }
}
