package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.ss.usermodel.Workbook;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;


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
        // Reject workbooks whose XML parts declare a DTD before the (XXE-prone) reader parses them.
        rejectXmlWithDoctype(file.getInputStream());
        StreamingReader.builder().open(file.getInputStream());
    }


    /**
     * Walk every XML part of the xlsx (zip) package with a hardened StAX reader and
     * fail closed if any part contains a DOCTYPE declaration (the vector for XXE).
     */
    private static void rejectXmlWithDoctype(InputStream in) throws IOException {
        XMLInputFactory xif = XMLInputFactory.newInstance();
        xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xif.setProperty(XMLInputFactory.SUPPORT_DTD, true);  // keep DTD visible so it can be rejected
        xif.setXMLResolver((publicID, systemID, baseURI, namespace) -> {
            throw new XMLStreamException("External entity resolution is disabled");
        });

        try (ZipInputStream zip = new ZipInputStream(in)) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                String name = entry.getName().toLowerCase(Locale.ROOT);
                if (entry.isDirectory() || !(name.endsWith(".xml") || name.endsWith(".rels") || name.endsWith(".vml"))) {
                    continue;
                }
                XMLStreamReader reader = xif.createXMLStreamReader(zip);
                try {
                    while (reader.hasNext()) {
                        if (reader.next() == XMLStreamConstants.DTD) {
                            throw new IOException("DOCTYPE declarations are not allowed in xlsx XML parts");
                        }
                    }
                } finally {
                    reader.close();  // does not close the underlying zip stream
                }
            }
        } catch (XMLStreamException e) {
            throw new IOException("Invalid or unsafe XML in xlsx", e);
        }
    }


    public static void main(String[] args) throws Exception {
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
