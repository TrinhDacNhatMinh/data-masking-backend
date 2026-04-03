package com.minh.data_masking.dto.auth;

public record JwtResponse(
        String accessToken,
        String tokenType,   // Always "Bearer"
        String email,       // Plaintext email (for client display)
        String role         // e.g. "ROLE_USER" or "ROLE_ADMIN"
) {

    public JwtResponse(String accessToken, String email, String role) {
        this(accessToken, "Bearer", email, role);
    }

}
