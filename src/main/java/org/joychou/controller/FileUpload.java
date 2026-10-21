package org.joychou.controller;

import com.fasterxml.uuid.Generators;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

import org.joychou.security.SecurityUtil;


/**
 * File upload.
 *
 * @author JoyChou @ 2018-08-15
 */
@Controller
@RequestMapping("/file")
public class FileUpload {

    // Save the uploaded file to this folder
    private static final String UPLOADED_FOLDER = "/tmp/";
    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private static String randomFilePath = "";

    // uplaod any file
    @GetMapping("/any")
    public String index() {
        return "upload"; // return upload.html page
    }

    // only allow to upload pictures
    @GetMapping("/pic")
    public String uploadPic() {
        return "uploadPic"; // return uploadPic.html page
    }

    @PostMapping("/upload")
    public String singleFileUpload(@RequestParam("file") MultipartFile file,
                                   RedirectAttributes redirectAttributes) {
        if (file.isEmpty()) {
            // 赋值给uploadStatus.html里的动态参数message
            redirectAttributes.addFlashAttribute("message", "Please select a file to upload");
            return "redirect:/file/status";
        }

        try {
            // Get the file and save it somewhere
            byte[] bytes = file.getBytes();
            String safeName = sanitizeFileName(file.getOriginalFilename());
            if (safeName == null) {
                redirectAttributes.addFlashAttribute("message", "Invalid file name");
                return "redirect:/file/status";
            }
            Path path = safeResolvePath(UPLOADED_FOLDER, safeName);
            if (path == null) {
                redirectAttributes.addFlashAttribute("message", "Invalid file path");
                return "redirect:/file/status";
            }
            Files.write(path, bytes);

            redirectAttributes.addFlashAttribute("message",
                    "You successfully uploaded '" + path.toString() + "'");

        } catch (IOException e) {
            redirectAttributes.addFlashAttribute("message", "upload failed");
            logger.error(e.toString());
        }

        return "redirect:/file/status";
    }

    @GetMapping("/status")
    public String uploadStatus() {
        return "uploadStatus";
    }

    // only upload picture
    @PostMapping("/upload/picture")
    @ResponseBody
    public String uploadPicture(@RequestParam("file") MultipartFile multifile) throws Exception {
        if (multifile.isEmpty()) {
            return "Please select a file to upload";
        }

        String fileName = multifile.getOriginalFilename();
        String safeName = sanitizeFileName(fileName);
        if (safeName == null) {
            return "Upload failed. Invalid file name.";
        }
        String Suffix = safeName.substring(safeName.lastIndexOf(".")); // 获取文件后缀名
        String mimeType = multifile.getContentType(); // 获取MIME类型
        Path safeFilePath = safeResolvePath(UPLOADED_FOLDER, safeName);
        if (safeFilePath == null) {
            return "Upload failed. Invalid file path.";
        }
        String filePath = safeFilePath.toString();
        File excelFile = convert(multifile);


        // 判断文件后缀名是否在白名单内  校验1
        String[] picSuffixList = {".jpg", ".png", ".jpeg", ".gif", ".bmp", ".ico"};
        boolean suffixFlag = false;
        for (String white_suffix : picSuffixList) {
            if (Suffix.toLowerCase().equals(white_suffix)) {
                suffixFlag = true;
                break;
            }
        }
        if (!suffixFlag) {
            logger.error("[-] Suffix error: " + Suffix);
            deleteFile(filePath);
            return "Upload failed. Illeagl picture.";
        }


        // 判断MIME类型是否在黑名单内 校验2
        String[] mimeTypeBlackList = {
                "text/html",
                "text/javascript",
                "application/javascript",
                "application/ecmascript",
                "text/xml",
                "application/xml"
        };
        for (String blackMimeType : mimeTypeBlackList) {
            // 用contains是为了防止text/html;charset=UTF-8绕过
            if (SecurityUtil.replaceSpecialStr(mimeType).toLowerCase().contains(blackMimeType)) {
                logger.error("[-] Mime type error: " + mimeType);
                deleteFile(filePath);
                return "Upload failed. Illeagl picture.";
            }
        }

        // 判断文件内容是否是图片 校验3
        boolean isImageFlag = isImage(excelFile);
        deleteFile(randomFilePath);

        if (!isImageFlag) {
            logger.error("[-] File is not Image");
            deleteFile(filePath);
            return "Upload failed. Illeagl picture.";
        }


        try {
            // Get the file and save it somewhere
            byte[] bytes = multifile.getBytes();
            Files.write(safeFilePath, bytes);
        } catch (IOException e) {
            logger.error(e.toString());
            deleteFile(filePath);
            return "Upload failed";
        }

        logger.info("[+] Safe file. Suffix: {}, MIME: {}", Suffix, mimeType);
        logger.info("[+] Successfully uploaded {}", filePath);
        return String.format("You successfully uploaded '%s'", filePath);
    }

    private void deleteFile(String filePath) {
        Path delPath = Paths.get(filePath).normalize();
        Path baseDir = Paths.get(UPLOADED_FOLDER).normalize();
        if (!delPath.startsWith(baseDir)) {
            logger.error("Attempted to delete file outside upload directory: " + filePath);
            return;
        }
        File delFile = delPath.toFile();
        if(delFile.isFile() && delFile.exists()) {
            if (delFile.delete()) {
                logger.info("[+] " + filePath + " delete successfully!");
                return;
            }
        }
        logger.info(filePath + " delete failed!");
    }

    /**
     * 为了使用ImageIO.read()
     *
     * 不建议使用transferTo，因为原始的MultipartFile会被覆盖
     * https://stackoverflow.com/questions/24339990/how-to-convert-a-multipart-file-to-file
     */
    private File convert(MultipartFile multiFile) throws Exception {
        String fileName = multiFile.getOriginalFilename();
        String safeName = sanitizeFileName(fileName);
        if (safeName == null) {
            return null;
        }
        String suffix = safeName.substring(safeName.lastIndexOf("."));
        UUID uuid = Generators.timeBasedGenerator().generate();
        String randomName = uuid + suffix;
        Path resolvedPath = safeResolvePath(UPLOADED_FOLDER, randomName);
        if (resolvedPath == null) {
            return null;
        }
        randomFilePath = resolvedPath.toString();
        // 随机生成一个同后缀名的文件
        File convFile = resolvedPath.toFile();
        boolean ret = convFile.createNewFile();
        if (!ret) {
            return null;
        }
        FileOutputStream fos = new FileOutputStream(convFile);
        fos.write(multiFile.getBytes());
        fos.close();
        return convFile;
    }

    /**
     * Check if the file is a picture.
     */
    private static boolean isImage(File file) throws IOException {
        BufferedImage bi = ImageIO.read(file);
        return bi != null;
    }

    /**
     * Sanitize the original file name by stripping any directory components
     * and rejecting names containing path traversal sequences.
     *
     * @return the base file name, or null if the name is invalid
     */
    private static String sanitizeFileName(String originalName) {
        if (originalName == null || originalName.isEmpty()) {
            return null;
        }
        // Strip any directory path (forward/backward slash)
        String baseName = originalName.replace("\\", "/");
        int lastSlash = baseName.lastIndexOf('/');
        if (lastSlash >= 0) {
            baseName = baseName.substring(lastSlash + 1);
        }
        // Reject if empty after stripping, or contains ".."
        if (baseName.isEmpty() || baseName.contains("..")) {
            return null;
        }
        return baseName;
    }

    /**
     * Safely resolve a file name within the given base directory.
     * Returns the canonical path only if it falls within the base directory.
     *
     * @return the resolved Path, or null if it escapes the base directory
     */
    private static Path safeResolvePath(String baseDir, String fileName) {
        Path base = Paths.get(baseDir).toAbsolutePath().normalize();
        Path resolved = base.resolve(fileName).normalize();
        if (!resolved.startsWith(base)) {
            return null;
        }
        return resolved;
    }
}
