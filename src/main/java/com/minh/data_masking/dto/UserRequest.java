package com.minh.data_masking.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record UserRequest(

        @NotBlank(message = "Full name must not be blank")
        String fullName,

        @NotBlank(message = "National ID must not be blank")
        @Size(min = 12, max = 12, message = "National ID must be exactly 12 digits")
        @Pattern(regexp = "\\d{12}", message = "National ID must contain digits only")
        String cccd,

        @NotBlank(message = "Email must not be blank")
        @Email(message = "Email format is invalid")
        String email,

        @NotBlank(message = "Phone number must not be blank")
        @Pattern(regexp = "^(0[3|5|7|8|9])\\d{8}$", message = "Phone number must be a valid Vietnamese number")
        String phone

) {}
