package com.syntrace.controller;

import com.syntrace.chat.ChatRequest;
import com.syntrace.chat.ChatResponse;
import com.syntrace.chat.ChatService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * MODULE 2 - conversational investigation API. Answers are generated locally from
 * correlated evidence; no request leaves the enclave.
 */
@RestController
@RequestMapping("/api/chat")
@RequiredArgsConstructor
@Tag(name = "Assistant", description = "Offline natural language questions about an incident")
public class ChatController {

    private final ChatService chatService;

    /**
     * @param request analyst question
     * @return grounded answer with citations
     */
    @PostMapping
    @Operation(summary = "Ask the offline assistant a question about an incident")
    public ResponseEntity<ChatResponse> ask(@Valid @RequestBody ChatRequest request) {
        return ResponseEntity.ok(chatService.ask(request));
    }

    /**
     * Real-time Server-Sent Events (SSE) streaming endpoint for token-by-token rendering.
     */
    @PostMapping(value = "/stream", produces = org.springframework.http.MediaType.TEXT_EVENT_STREAM_VALUE)
    @Operation(summary = "Stream assistant answer token-by-token over Server-Sent Events")
    public org.springframework.web.servlet.mvc.method.annotation.SseEmitter streamAsk(@Valid @RequestBody ChatRequest request) {
        org.springframework.web.servlet.mvc.method.annotation.SseEmitter emitter = new org.springframework.web.servlet.mvc.method.annotation.SseEmitter(60000L);
        
        java.util.concurrent.CompletableFuture.runAsync(() -> {
            try {
                ChatResponse response = chatService.ask(request);
                String text = response.answer();
                String[] words = text.split("(?<=\\s)|(?=\\n)");
                
                for (String word : words) {
                    emitter.send(org.springframework.web.servlet.mvc.method.annotation.SseEmitter.event()
                            .data(word)
                            .name("token"));
                    Thread.sleep(25); // Smooth streaming pacing
                }
                emitter.send(org.springframework.web.servlet.mvc.method.annotation.SseEmitter.event()
                        .data("[DONE]")
                        .name("complete"));
                emitter.complete();
            } catch (Exception e) {
                emitter.completeWithError(e);
            }
        });
        return emitter;
    }

    /**
     * @return suggested opening questions for the console
     */
    @GetMapping("/suggestions")
    @Operation(summary = "Starter questions shown in the assistant panel")
    public ResponseEntity<List<String>> suggestions() {
        return ResponseEntity.ok(chatService.starterQuestions());
    }
}
