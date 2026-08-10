package com.syntrace.service;

import com.syntrace.config.SynTraceProperties;
import com.syntrace.exception.InvalidUploadException;
import com.syntrace.exception.StorageException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDate;
import java.util.HexFormat;
import java.util.Locale;
import java.util.UUID;

/**
 * Writes uploaded evidence to the local vault. Nothing ever leaves the machine, which is
 * the entire point of an air-gapped analysis platform.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class FileStorageService {

    private final SynTraceProperties properties;

    /**
     * Validates, stores and fingerprints an uploaded file.
     *
     * @param file multipart upload
     * @return where it landed plus its SHA-256
     */
    public StoredFile store(MultipartFile file) {
        String originalName = StringUtils.cleanPath(
                file.getOriginalFilename() == null ? "evidence.log" : file.getOriginalFilename());
        validate(file, originalName);

        Path directory = Path.of(properties.getStorage().getRoot(), LocalDate.now().toString());
        Path target = directory.resolve(UUID.randomUUID() + "-" + originalName);

        try {
            Files.createDirectories(directory);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream in = file.getInputStream();
                 DigestInputStream digesting = new DigestInputStream(in, digest)) {
                Files.copy(digesting, target, StandardCopyOption.REPLACE_EXISTING);
            }
            String checksum = HexFormat.of().formatHex(digest.digest());
            log.debug("Stored evidence {} ({} bytes, sha256={})", originalName, file.getSize(), checksum);
            return new StoredFile(originalName, target, file.getSize(), checksum, extensionOf(originalName),
                    file.getContentType());
        } catch (IOException ex) {
            throw new StorageException("Failed to store evidence file " + originalName, ex);
        } catch (NoSuchAlgorithmException ex) {
            throw new StorageException("SHA-256 is unavailable in this JVM", ex);
        }
    }

    private void validate(MultipartFile file, String originalName) {
        if (file.isEmpty()) {
            throw new InvalidUploadException("Evidence file '" + originalName + "' is empty");
        }
        if (file.getSize() > properties.getStorage().getMaxFileSizeBytes()) {
            throw new InvalidUploadException("Evidence file '" + originalName + "' exceeds the maximum allowed size");
        }
        if (originalName.contains("..")) {
            throw new InvalidUploadException("Illegal path sequence in file name " + originalName);
        }
        String extension = extensionOf(originalName);
        if (!properties.getStorage().getAllowedExtensions().contains(extension)) {
            throw new InvalidUploadException("Unsupported evidence type '." + extension
                    + "'. Allowed: " + properties.getStorage().getAllowedExtensions());
        }
    }

    private String extensionOf(String fileName) {
        int dot = fileName.lastIndexOf('.');
        return dot < 0 ? "" : fileName.substring(dot + 1).toLowerCase(Locale.ROOT);
    }

    /**
     * Result of a successful store operation.
     *
     * @param originalFilename uploaded name
     * @param path             on-disk location
     * @param sizeBytes        byte count
     * @param checksumSha256   integrity fingerprint
     * @param extension        lower-cased extension
     * @param contentType      declared MIME type
     */
    public record StoredFile(
            String originalFilename,
            Path path,
            long sizeBytes,
            String checksumSha256,
            String extension,
            String contentType) {
    }
}
