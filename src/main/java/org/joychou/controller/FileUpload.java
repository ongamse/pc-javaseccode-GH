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

import org.apache.commons.io.FilenameUtils;
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
            String sanitizedName = FilenameUtils.getName(file.getOriginalFilename());
            Path path = Paths.get(UPLOADED_FOLDER + sanitizedName);
            Files.write(path, bytes);

            redirectAttributes.addFlashAttribute("message",
                    "You successfully uploaded '" + UPLOADED_FOLDER + sanitizedName + "'");

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

        String fileName = FilenameUtils.getName(multifile.getOriginalFilename());
        String Suffix = fileName.substring(fileName.lastIndexOf(".")); // 获取文件后缀名
        String mimeType = multifile.getContentType(); // 获取MIME类型
        String filePath = UPLOADED_FOLDER + fileName;
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
            Path path = Paths.get(UPLOADED_FOLDER + fileName);
            Files.write(path, bytes);
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
        try {
            File delFile = new File(filePath).getCanonicalFile();
            File allowedDir = new File(UPLOADED_FOLDER).getCanonicalFile();
            String allowedPrefix = allowedDir.getCanonicalPath() + File.separator;
            if (!delFile.getCanonicalPath().startsWith(allowedPrefix)
                    && !delFile.getCanonicalPath().equals(allowedDir.getCanonicalPath())) {
                logger.error("Blocked path traversal in deleteFile: " + filePath);
                return;
            }
            if (delFile.isFile() && delFile.exists()) {
                if (delFile.delete()) {
                    logger.info("[+] " + filePath + " delete successfully!");
                    return;
                }
            }
            logger.info(filePath + " delete failed!");
        } catch (IOException e) {
            logger.error("Error resolving canonical path for deleteFile: " + e.getMessage());
        }
    }

    /**
     * 为了使用ImageIO.read()
     *
     * 不建议使用transferTo，因为原始的MultipartFile会被覆盖
     * https://stackoverflow.com/questions/24339990/how-to-convert-a-multipart-file-to-file
     */
    private File convert(MultipartFile multiFile) throws Exception {
        String fileName = FilenameUtils.getName(multiFile.getOriginalFilename());
        String suffix = fileName.substring(fileName.lastIndexOf("."));
        UUID uuid = Generators.timeBasedGenerator().generate();
        randomFilePath = UPLOADED_FOLDER + uuid + suffix;
        // 随机生成一个同后缀名的文件
        File convFile = new File(randomFilePath);
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
}
