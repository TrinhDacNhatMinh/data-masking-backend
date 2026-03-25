package com.minh.data_masking.dto;

import lombok.Builder;

@Builder
public record UserResponse(
        String fullName,
        String maskedCccd,
        String maskedEmail,
        String maskedPhone
) {
}
