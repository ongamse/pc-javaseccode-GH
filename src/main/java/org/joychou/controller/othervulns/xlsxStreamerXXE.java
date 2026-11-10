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


    @GetMapping("/upload")
    public String index() {
        return "xxe_upload"; // return xxe_upload.html page
    }


    @PostMapping("/readxlsx")
    public void xllx_streamer_xxe(MultipartFile file) throws IOException {
        byte[] data = file.getBytes();
        rejectDoctypeInXmlParts(data);
        StreamingReader.builder().open(new ByteArrayInputStream(data));
    }

    /**
     * Reject xlsx packages whose XML parts declare a DTD or entities (XXE).
     */
    private static void rejectDoctypeInXmlParts(byte[] data) throws IOException {
        final int maxEntryBytes = 32 * 1024 * 1024;
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(data))) {
            ZipEntry entry;
            byte[] buf = new byte[8192];
            while ((entry = zis.getNextEntry()) != null) {
                String name = entry.getName().toLowerCase(Locale.ROOT);
                if (!(name.endsWith(".xml") || name.endsWith(".rels"))) {
                    continue;
                }
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                int n;
                while ((n = zis.read(buf)) > 0) {
                    out.write(buf, 0, n);
                    if (out.size() > maxEntryBytes) {
                        throw new IOException("xml part too large");
                    }
                }
                // drop NUL bytes so UTF-16 encoded markup is also detected
                StringBuilder sb = new StringBuilder(out.size());
                for (byte b : out.toByteArray()) {
                    if (b != 0) {
                        sb.append((char) (b & 0xff));
                    }
                }
                String content = sb.toString().toUpperCase(Locale.ROOT);
                if (content.contains("<!DOCTYPE") || content.contains("<!ENTITY")) {
                    throw new IOException("DTD / entity declarations are not allowed");
                }
            }
        }
    }


    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
