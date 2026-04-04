package com.minh.data_masking.dto.auth;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class EncryptedRegisterRequest {
    @NotBlank(message = "Payload bị thiếu")
    private String encryptedPayload;

    @NotBlank(message = "Session Key bị thiếu")
    private String encryptedSessionKey;
}