package org.joychou.controller;

import org.apache.commons.codec.binary.Base64;
import org.joychou.security.SecurityUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

@RestController
public class PathTraversal {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * Allowed base directory for serving images.
     */
    private static final String IMAGE_BASE_DIR = System.getProperty("user.dir");

    /**
     * Validate that the given file path resolves within the allowed base directory.
     *
     * @param filePath the user-supplied file path
     * @param baseDir  the allowed base directory
     * @return the canonical path if valid
     * @throws IOException if the path is outside the allowed directory or invalid
     */
    private String validateAndResolvePath(String filePath, String baseDir) throws IOException {
        if (filePath == null || filePath.isEmpty()) {
            throw new IOException("File path is empty");
        }
        File base = new File(baseDir).getCanonicalFile();
        File resolved = new File(baseDir, filePath).getCanonicalFile();
        if (!resolved.toPath().startsWith(base.toPath())) {
            throw new IOException("Path traversal detected: path resolves outside the allowed directory");
        }
        return resolved.getPath();
    }

    /**
     * http://localhost:8080/path_traversal/vul?filepath=../../../../../etc/passwd
     */
    @GetMapping("/path_traversal/vul")
    public String getImage(String filepath) throws IOException {
        return getImgBase64(filepath);
    }

    @GetMapping("/path_traversal/sec")
    public String getImageSec(String filepath) throws IOException {
        if (SecurityUtil.pathFilter(filepath) == null) {
            logger.info("Illegal file path: " + filepath);
            return "Bad boy. Illegal file path.";
        }
        return getImgBase64(filepath);
    }

    private String getImgBase64(String imgFile) throws IOException {

        logger.info("Working directory: " + System.getProperty("user.dir"));
        logger.info("File path: " + imgFile);

        // Canonicalize and validate path within the allowed base directory
        String resolvedPath;
        try {
            resolvedPath = validateAndResolvePath(imgFile, IMAGE_BASE_DIR);
        } catch (IOException e) {
            logger.error("Path traversal rejected: " + e.getMessage());
            return "Illegal file path.";
        }

        File f = new File(resolvedPath);
        if (f.exists() && !f.isDirectory()) {
            byte[] data = Files.readAllBytes(f.toPath());
            return new String(Base64.encodeBase64(data));
        } else {
            return "File doesn't exist or is not a file.";
        }
    }

    public static void main(String[] argv) throws IOException {
        String aa = new String(Files.readAllBytes(Paths.get("pom.xml")), StandardCharsets.UTF_8);
        System.out.println(aa);
    }
}