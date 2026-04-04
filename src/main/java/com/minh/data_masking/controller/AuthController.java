package com.minh.data_masking.controller;

import com.minh.data_masking.dto.auth.*;
import com.minh.data_masking.service.AuthService;
import com.minh.data_masking.util.RsaService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map; // Khả năng cao bạn đang thiếu dòng import này lúc nãy

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final RsaService rsaService;

    /**
     * API Cấp phát Khóa Công khai RSA (Code Chay)
     * Trả về trực tiếp 2 số N và E dạng Hexa cho ReactJS
     */
    @GetMapping("/public-key")
    public ResponseEntity<Map<String, String>> getPublicKey() {
        return ResponseEntity.ok(rsaService.getRawPublicKey());
    }

    @PostMapping("/register")
    public ResponseEntity<MessageResponse> register(@Valid @RequestBody EncryptedRegisterRequest request) throws Exception {
        // Gọi thẳng vào hàm xử lý mã hóa lai thay vì hàm gốc
        return ResponseEntity.ok(authService.registerSecure(request));
    }

    @PostMapping("/login")
    public ResponseEntity<JwtResponse> login(@Valid @RequestBody EncryptedLoginRequest request) throws Exception {
        return ResponseEntity.ok(authService.loginSecure(request));
    }
}