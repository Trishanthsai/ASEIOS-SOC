package com.syntrace.service;

import com.syntrace.common.AppConstants;
import com.syntrace.config.SynTraceProperties;
import com.syntrace.exception.StorageException;
import com.syntrace.util.DateUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

/**
 * MODULE 4 - read, delete and temporary-file operations over the local evidence vault.
 *
 * <p>{@code FileStorageService} owns ingestion (validate, write, fingerprint). This service
 * owns everything that happens to a file afterwards: reading it back for re-analysis,
 * writing generated artefacts such as PDFs, creating scratch files, and purging evidence
 * when a case is closed.</p>
 *
 * <p>Every path is resolved against and re-checked inside {@code syntrace.storage.root}, so
 * a crafted file name can never read or delete outside the vault.</p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class StorageService {

    private final SynTraceProperties properties;

    /** @return absolute, normalized vault root, created on demand */
    public Path root() {
        Path root = Path.of(properties.getStorage().getRoot()).toAbsolutePath().normalize();
        return ensureDirectory(root);
    }

    /** @return directory holding generated reports */
    public Path reportDirectory() {
        return ensureDirectory(root().resolve(AppConstants.REPORT_DIRECTORY));
    }

    /** @return directory holding transient working files */
    public Path tempDirectory() {
        return ensureDirectory(root().resolve(AppConstants.TEMP_DIRECTORY));
    }

    /**
     * Reads a stored evidence file as UTF-8 lines.
     *
     * @param path location previously returned by the storage layer
     * @return every line in file order
     */
    public List<String> readLines(Path path) {
        Path safe = requireInsideVault(path);
        try {
            return Files.readAllLines(safe, StandardCharsets.UTF_8);
        } catch (IOException ex) {
            throw new StorageException("Unable to read evidence file " + safe.getFileName(), ex);
        }
    }

    /**
     * @param path location previously returned by the storage layer
     * @return the raw bytes of a stored artefact
     */
    public byte[] readBytes(Path path) {
        Path safe = requireInsideVault(path);
        try {
            return Files.readAllBytes(safe);
        } catch (IOException ex) {
            throw new StorageException("Unable to read artefact " + safe.getFileName(), ex);
        }
    }

    /**
     * @param path candidate location
     * @return {@code true} when a readable regular file exists there
     */
    public boolean exists(Path path) {
        Path safe = requireInsideVault(path);
        return Files.isRegularFile(safe) && Files.isReadable(safe);
    }

    /**
     * @param path candidate location
     * @return file size in bytes, or {@code 0} when absent
     */
    public long sizeOf(Path path) {
        Path safe = requireInsideVault(path);
        try {
            return Files.exists(safe) ? Files.size(safe) : 0L;
        } catch (IOException ex) {
            throw new StorageException("Unable to stat " + safe.getFileName(), ex);
        }
    }

    /**
     * Writes a generated artefact - typically a PDF - into the report directory.
     *
     * @param fileName desired file name, sanitised before use
     * @param content  bytes to persist
     * @return where the artefact landed
     */
    public Path writeReport(String fileName, byte[] content) {
        Path target = reportDirectory().resolve(safeName(fileName));
        try {
            Files.write(target, content);
            log.info("STORAGE - wrote report {} ({} bytes)", target.getFileName(), content.length);
            return target;
        } catch (IOException ex) {
            throw new StorageException("Unable to write report " + fileName, ex);
        }
    }

    /**
     * Creates an empty scratch file that callers are expected to delete.
     *
     * @param prefix    logical name
     * @param extension extension without the dot
     * @return path to the new temporary file
     */
    public Path createTempFile(String prefix, String extension) {
        try {
            Path file = tempDirectory().resolve(
                    safeName(prefix) + "-" + DateUtil.fileStamp(Instant.now()) + "-"
                            + UUID.randomUUID().toString().substring(0, 8) + "." + safeName(extension));
            Files.createFile(file);
            return file;
        } catch (IOException ex) {
            throw new StorageException("Unable to create temporary file for " + prefix, ex);
        }
    }

    /**
     * Moves a temporary file to its permanent home inside the vault.
     *
     * @param temp       scratch file
     * @param targetName final file name
     * @return final location
     */
    public Path promote(Path temp, String targetName) {
        Path source = requireInsideVault(temp);
        Path target = reportDirectory().resolve(safeName(targetName));
        try {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
            return target;
        } catch (IOException ex) {
            throw new StorageException("Unable to promote temporary file " + source.getFileName(), ex);
        }
    }

    /**
     * Deletes a single stored file. Missing files are not an error - deletion is idempotent
     * so that retrying a case purge always converges.
     *
     * @param path file to remove
     * @return {@code true} when a file was actually deleted
     */
    public boolean delete(Path path) {
        Path safe = requireInsideVault(path);
        try {
            boolean deleted = Files.deleteIfExists(safe);
            if (deleted) {
                log.info("STORAGE - deleted {}", safe.getFileName());
            }
            return deleted;
        } catch (IOException ex) {
            throw new StorageException("Unable to delete " + safe.getFileName(), ex);
        }
    }

    /**
     * Recursively removes a directory, used when an investigation is purged.
     *
     * @param directory directory inside the vault
     * @return number of files removed
     */
    public long deleteDirectory(Path directory) {
        Path safe = requireInsideVault(directory);
        if (!Files.isDirectory(safe)) {
            return 0L;
        }
        try (Stream<Path> walk = Files.walk(safe)) {
            long removed = walk.sorted(Comparator.reverseOrder())
                    .filter(Files::isRegularFile)
                    .peek(this::deleteQuietly)
                    .count();
            Files.deleteIfExists(safe);
            log.info("STORAGE - purged {} ({} files)", safe.getFileName(), removed);
            return removed;
        } catch (IOException ex) {
            throw new StorageException("Unable to purge " + safe.getFileName(), ex);
        }
    }

    /**
     * Removes scratch files older than the supplied age. Intended for a scheduled sweep.
     *
     * @param olderThanHours retention window in hours
     * @return number of files removed
     */
    public long purgeTemp(int olderThanHours) {
        Instant cutoff = Instant.now().minusSeconds(Math.max(1, olderThanHours) * 3600L);
        try (Stream<Path> files = Files.list(tempDirectory())) {
            return files.filter(Files::isRegularFile)
                    .filter(file -> lastModified(file).isBefore(cutoff))
                    .peek(this::deleteQuietly)
                    .count();
        } catch (IOException ex) {
            throw new StorageException("Unable to sweep the temporary directory", ex);
        }
    }

    /**
     * @param content bytes to fingerprint
     * @return lower-case SHA-256 hex digest, used for chain of custody
     */
    public String sha256(byte[] content) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
        } catch (NoSuchAlgorithmException ex) {
            throw new StorageException("SHA-256 is unavailable in this JVM", ex);
        }
    }

    // ----------------------------------------------------------------- internals

    private Path requireInsideVault(Path path) {
        if (path == null) {
            throw new StorageException("No path supplied");
        }
        Path root = Path.of(properties.getStorage().getRoot()).toAbsolutePath().normalize();
        Path resolved = path.isAbsolute() ? path.normalize() : root.resolve(path).normalize();
        if (!resolved.startsWith(root)) {
            throw new StorageException("Refusing to touch a path outside the evidence vault: " + path);
        }
        return resolved;
    }

    private Path ensureDirectory(Path directory) {
        try {
            Files.createDirectories(directory);
            return directory;
        } catch (IOException ex) {
            throw new StorageException("Unable to create directory " + directory, ex);
        }
    }

    private String safeName(String value) {
        String cleaned = value == null ? "file" : value.replaceAll("[^A-Za-z0-9._-]", "_");
        return cleaned.isBlank() ? "file" : cleaned;
    }

    private Instant lastModified(Path file) {
        try {
            return Files.getLastModifiedTime(file).toInstant();
        } catch (IOException ex) {
            throw new UncheckedIOException(ex);
        }
    }

    private void deleteQuietly(Path file) {
        try {
            Files.deleteIfExists(file);
        } catch (IOException ex) {
            log.warn("STORAGE - could not delete {}: {}", file, ex.getMessage());
        }
    }
}
