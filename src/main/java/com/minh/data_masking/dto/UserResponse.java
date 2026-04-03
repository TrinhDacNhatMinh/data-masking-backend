package com.minh.data_masking.dto;

import lombok.Builder;

@Builder
public record UserResponse(
        Long id,
        String fullName,

        // ── Masked fields (visible to everyone) ──────────────────────────────
        String maskedCccd,
        String maskedEmail,
        String maskedPhone,

        // ── Clear fields (only populated for the owner) ───────────────────────
        String cccd,
        String email,
        String phone,

        // ── Metadata ─────────────────────────────────────────────────────────
        String role,
        boolean isOwner   // tells the client which record belongs to them
) {
}
