package com.syntrace.controller;

import com.syntrace.dto.UploadResponse;
import com.syntrace.service.LogAnalysisService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

/**
 * MODULE 8 - Upload API.
 */
@Slf4j
@RestController
@RequestMapping("/api/logs")
@RequiredArgsConstructor
@Tag(name = "Log Ingestion", description = "Upload evidence and run the full analysis pipeline")
public class LogUploadController {

    private final LogAnalysisService logAnalysisService;

    /**
     * Uploads a single evidence file and returns the complete investigation.
     *
     * @param file evidence file ({@code .log}, {@code .txt}, {@code .csv}, {@code .json})
     * @param name optional investigation name
     * @return complete investigation response
     */
    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    @Operation(summary = "Upload one evidence file and run parse, detect, correlate and explain")
    public ResponseEntity<UploadResponse> upload(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "name", required = false) String name) {
        log.info("Received evidence upload: {} ({} bytes)", file.getOriginalFilename(), file.getSize());
        return ResponseEntity.status(HttpStatus.CREATED).body(logAnalysisService.analyze(file, name));
    }

    /**
     * Uploads several evidence files that are correlated together as one investigation.
     *
     * @param files evidence files
     * @param name  optional investigation name
     * @return complete investigation response
     */
    @PostMapping(value = "/upload/batch", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("hasAnyRole('ADMIN','ANALYST')")
    @Operation(summary = "Upload multiple evidence files analysed as a single investigation")
    public ResponseEntity<UploadResponse> uploadBatch(
            @RequestParam("files") List<MultipartFile> files,
            @RequestParam(value = "name", required = false) String name) {
        log.info("Received batch evidence upload of {} file(s)", files.size());
        return ResponseEntity.status(HttpStatus.CREATED).body(logAnalysisService.analyze(files, name));
    }
}
