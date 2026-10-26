package org.joychou.controller.othervulns;

import com.monitorjbl.xlsx.StreamingReader;
import org.apache.poi.ss.usermodel.Workbook;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import javax.xml.XMLConstants;
import java.io.FileInputStream;
import java.io.IOException;


/**
 * Desc:  xlsx-streamer xxe - secured via system properties disabling external entities
 * Usage: xl/workbook.xml
 * Ref:   https://www.itread01.com/hkpcyyp.html
 *
 * @author JoyChou @2019-09-05
 */
@Controller
@RequestMapping("xlsx-streamer")
public class xlsxStreamerXXE {

    /**
     * Set JVM-wide system properties so that any SAXParserFactory.newInstance()
     * call (including inside xlsx-streamer) produces a parser with external
     * entities and DTDs disabled. This is the code-level mitigation when the
     * library does not expose parser configuration.
     */
    private static void setSecureXmlDefaults() {
        System.setProperty("javax.xml.parsers.SAXParserFactory",
                "com.sun.org.apache.xerces.internal.jaxp.SAXParserFactoryImpl");
        // ACCESS_EXTERNAL_DTD and ACCESS_EXTERNAL_SCHEMA empty = disallow all
        System.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        System.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    }


    @GetMapping("/upload")
    public String index() {
        return "xxe_upload"; // return xxe_upload.html page
    }


    @PostMapping("/readxlsx")
    public void xllx_streamer_xxe(MultipartFile file) throws IOException {
        setSecureXmlDefaults();
        StreamingReader.builder().open(file.getInputStream());
    }


    public static void main(String[] args) throws Exception {
        setSecureXmlDefaults();
        StreamingReader.builder().open((new FileInputStream("poc.xlsx")));
    }
}
