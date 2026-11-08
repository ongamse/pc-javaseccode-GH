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

    private static final int MAX_XML_PART_BYTES = 32 * 1024 * 1024;

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
     * xlsx-streamer 2.0.0 parses the XML parts of the uploaded package with a default
     * (entity-resolving) parser. Reject any package whose XML parts declare a DOCTYPE or
     * ENTITY (or use a non-UTF-8 encoding that could hide one) before it reaches the parser.
     */
    private static void rejectXmlWithDoctype(byte[] content) throws IOException {
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(content))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName().toLowerCase(Locale.ROOT);
                if (!(name.endsWith(".xml") || name.endsWith(".rels") || name.endsWith(".vml"))) {
                    continue;
                }
                ByteArrayOutputStream buf = new ByteArrayOutputStream();
                byte[] chunk = new byte[8192];
                int n;
                while ((n = zis.read(chunk)) != -1) {
                    buf.write(chunk, 0, n);
                    if (buf.size() > MAX_XML_PART_BYTES) {
                        throw new IOException("xlsx xml part too large");
                    }
                }
                byte[] part = buf.toByteArray();
                if (hasNonUtf8Marker(part)) {
                    throw new IOException("unsupported xml encoding in xlsx");
                }
                String text = new String(part, StandardCharsets.UTF_8).toLowerCase(Locale.ROOT);
                if (text.contains("<!doctype") || text.contains("<!entity")) {
                    throw new IOException("DOCTYPE/ENTITY is not allowed in xlsx xml");
                }
            }
        }
    }

    private static boolean hasNonUtf8Marker(byte[] part) {
        if (part.length >= 2) {
            int b0 = part[0] & 0xFF;
            int b1 = part[1] & 0xFF;
            if ((b0 == 0xFE && b1 == 0xFF) || (b0 == 0xFF && b1 == 0xFE)) {
                return true;  // UTF-16 BOM
            }
        }
        // NUL bytes in the head indicate UTF-16/UTF-32 without BOM
        for (int i = 0; i < Math.min(part.length, 64); i++) {
            if (part[i] == 0) {
                return true;
            }
        }
        if (part.length >= 4 && (part[0] & 0xFF) == 0x4C && (part[1] & 0xFF) == 0x6F
                && (part[2] & 0xFF) == 0xA7 && (part[3] & 0xFF) == 0x94) {
            return true;  // EBCDIC "<?xm"
        }
        return false;
    }


    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
