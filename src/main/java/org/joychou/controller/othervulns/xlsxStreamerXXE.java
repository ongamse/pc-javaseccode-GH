package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.ss.usermodel.Workbook;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
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
        // xlsx-streamer 2.0.0 parses the XML parts with a default (XXE-prone) parser, so reject
        // any workbook whose XML parts carry a DTD / entity declaration before it is parsed.
        rejectXmlWithDtd(content);
        StreamingReader.builder().open(new ByteArrayInputStream(content));
    }


    /**
     * Fail closed: throw if any XML part of the OOXML package is not plain ASCII-compatible XML
     * or declares a DOCTYPE / ENTITY (the prerequisites for XXE).
     */
    private static void rejectXmlWithDtd(byte[] xlsx) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(xlsx))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName().toLowerCase(Locale.ROOT);
                if (entry.isDirectory() || !(name.endsWith(".xml") || name.endsWith(".rels") || name.endsWith(".vml"))) {
                    continue;
                }
                ByteArrayOutputStream bos = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int n;
                while ((n = zis.read(buf)) != -1) {
                    bos.write(buf, 0, n);
                }
                byte[] part = bos.toByteArray();
                int start = (part.length >= 3 && (part[0] & 0xFF) == 0xEF && (part[1] & 0xFF) == 0xBB
                        && (part[2] & 0xFF) == 0xBF) ? 3 : 0;
                // Non ASCII-compatible encodings (UTF-16/32, EBCDIC) could hide a DOCTYPE from the scan below.
                if (part.length > start && part[start] != '<') {
                    throw new IOException("Unsupported XML encoding in " + entry.getName());
                }
                for (byte b : part) {
                    if (b == 0) {
                        throw new IOException("Unsupported XML encoding in " + entry.getName());
                    }
                }
                String text = new String(part, StandardCharsets.ISO_8859_1);
                if (text.contains("<!DOCTYPE") || text.contains("<!ENTITY")) {
                    throw new IOException("DTD is not allowed in " + entry.getName());
                }
            }
        }
    }


    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
