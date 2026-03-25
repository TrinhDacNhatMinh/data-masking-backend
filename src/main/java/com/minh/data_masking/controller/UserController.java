package com.minh.data_masking.controller;

import com.minh.data_masking.dto.UserRequest;
import com.minh.data_masking.dto.UserResponse;
import com.minh.data_masking.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    /**
     * POST /api/users
     * Accepts plaintext → encrypts with AES → saves to Oracle DB → returns DTO (entity not exposed)
     * <p>
     * Request body:
     * {
     * "fullName": "Nguyen Van A",
     * "cccd": "012345678901",
     * "email": "test@gmail.com",
     * "phone": "0971234567"
     * }
     */
    @PostMapping
    public ResponseEntity<UserResponse> createUser(@Valid @RequestBody UserRequest request) {
        return ResponseEntity.ok(userService.saveUser(request));
    }

    /**
     * GET /api/users?page=0&size=10&sort=id,asc
     * Fetches from DB with pagination → decrypts → applies Data Masking → returns JSON
     * Spring auto-resolves Pageable from query params:
     *   ?page=0      → first page (0-indexed)
     *   ?size=10     → 10 records per page
     *   ?sort=id,asc → sort by id ascending
     */
    @GetMapping
    public ResponseEntity<Page<UserResponse>> getAllUsers(Pageable pageable) {
        return ResponseEntity.ok(userService.getAllUsers(pageable));
    }

}