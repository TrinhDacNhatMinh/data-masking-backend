package com.minh.data_masking.dto.auth;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class EncryptedLoginRequest {

    @NotBlank(message = "Thiếu gói dữ liệu mã hóa")
    private String encryptedPayload; // Chứa {email, password} đã mã hóa bằng AES

    @NotBlank(message = "Thiếu khóa phiên mã hóa")
    private String encryptedSessionKey; // Chứa Khóa AES đã mã hóa bằng RSA
}