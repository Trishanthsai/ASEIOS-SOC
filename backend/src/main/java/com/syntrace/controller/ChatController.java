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
     * @return suggested opening questions for the console
     */
    @GetMapping("/suggestions")
    @Operation(summary = "Starter questions shown in the assistant panel")
    public ResponseEntity<List<String>> suggestions() {
        return ResponseEntity.ok(chatService.starterQuestions());
    }
}
