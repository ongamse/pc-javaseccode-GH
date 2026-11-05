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

    private static final long MAX_XML_BYTES = 100L * 1024 * 1024;

    @GetMapping("/upload")
    public String index() {
        return "xxe_upload"; // return xxe_upload.html page
    }


    @PostMapping("/readxlsx")
    public void xllx_streamer_xxe(MultipartFile file) throws IOException {
        byte[] content = file.getBytes();
        rejectDoctype(content);
        StreamingReader.builder().open(new ByteArrayInputStream(content));
    }


    /**
     * The bundled xlsx-streamer parses the XML parts of the package without disabling DTDs.
     * Reject any package whose XML parts declare a DOCTYPE / ENTITY before handing it to the reader.
     */
    private static void rejectDoctype(byte[] content) throws IOException {
        long total = 0;
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(content))) {
            ZipEntry entry;
            byte[] buf = new byte[8192];
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName().toLowerCase(Locale.ROOT);
                if (!(name.endsWith(".xml") || name.endsWith(".rels") || name.endsWith(".vml"))) {
                    continue;
                }
                ByteArrayOutputStream part = new ByteArrayOutputStream();
                int n;
                while ((n = zis.read(buf)) != -1) {
                    total += n;
                    if (total > MAX_XML_BYTES) {
                        throw new IOException("xlsx xml content too large");
                    }
                    part.write(buf, 0, n);
                }
                // Drop NUL bytes so UTF-16 encoded declarations are detected as well.
                StringBuilder sb = new StringBuilder(part.size());
                for (byte b : part.toByteArray()) {
                    if (b != 0) {
                        sb.append((char) (b & 0xFF));
                    }
                }
                String text = sb.toString().toUpperCase(Locale.ROOT);
                if (text.contains("<!DOCTYPE") || text.contains("<!ENTITY")) {
                    throw new IOException("DOCTYPE is not allowed in xlsx xml parts");
                }
            }
        }
    }


    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
