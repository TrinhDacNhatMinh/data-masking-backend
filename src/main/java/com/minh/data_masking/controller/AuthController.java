package com.minh.data_masking.controller;

import com.minh.data_masking.dto.auth.JwtResponse;
import com.minh.data_masking.dto.auth.LoginRequest;
import com.minh.data_masking.dto.auth.MessageResponse;
import com.minh.data_masking.dto.auth.RegisterRequest;
import com.minh.data_masking.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for public Authentication endpoints.
 * Includes register and login.
 */
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * POST /api/auth/register
     * Registers a new user. Role is automatically set to ROLE_USER.
     */
    @PostMapping("/register")
    public ResponseEntity<MessageResponse> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(authService.register(request));
    }

    /**
     * POST /api/auth/login
     * Authenticates user using email and password, and returns a JWT response.
     */
    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }
}
