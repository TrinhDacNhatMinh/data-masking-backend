package com.minh.data_masking.service;

import com.minh.data_masking.dto.UserRequest;
import com.minh.data_masking.dto.UserResponse;
import com.minh.data_masking.model.SecUser;
import com.minh.data_masking.repository.SecUserRepository;
import com.minh.data_masking.util.AesService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
public class UserService {

    private final AesService aesService;
    private final MaskingService maskingService;
    private final SecUserRepository secUserRepository;

    // ──────────────────────────────────────────────────────────────────────────
    // Write operations
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Encrypts plaintext fields → saves ciphertext to DB → returns DTO (entity not exposed).
     * NOTE: This endpoint is for direct user creation (admin use). Normal registration
     * goes through AuthService.register() which also sets password and role.
     */
    @Transactional
    public UserResponse saveUser(UserRequest request) {
        SecUser user = SecUser.builder()
                .fullName(request.fullName())
                .cccd(aesService.encrypt(request.cccd()))
                .email(aesService.encrypt(request.email()))
                .phone(aesService.encrypt(request.phone()))
                .build();
        return toMaskedResponse(secUserRepository.save(user), false);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Read operations
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Fetches all users with pagination. Decrypts and masks sensitive fields.
     * The owner (authenticated user) sees their own data in cleartext;
     * all other users see masked data only.
     *
     * @param pageable    Spring pagination params
     * @param auth        Current authentication (null if unauthenticated, but endpoint is protected)
     */
    @Transactional(readOnly = true)
    public Page<UserResponse> getAllUsers(Pageable pageable, Authentication auth) {
        // The principal's username is the encrypted email (as stored in DB / set in JWT subject)
        String currentEncryptedEmail = extractEncryptedEmail(auth);

        return secUserRepository.findAll(pageable)
                .map(user -> {
                    boolean isOwner = user.getEmail().equals(currentEncryptedEmail);
                    return toResponse(user, isOwner);
                });
    }

    /**
     * Returns ALL users (no pagination) with owner-aware masking.
     * Useful for admin dashboards.
     */
    @Transactional(readOnly = true)
    public List<UserResponse> getUsers(Authentication auth) {
        String currentEncryptedEmail = extractEncryptedEmail(auth);

        return secUserRepository.findAll().stream()
                .map(user -> {
                    boolean isOwner = user.getEmail().equals(currentEncryptedEmail);
                    return toResponse(user, isOwner);
                })
                .toList();
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Private helpers
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Maps entity → DTO with owner-aware decryption/masking.
     *
     * @param user    the SecUser entity (sensitive fields are AES ciphertext)
     * @param isOwner true if this record belongs to the currently authenticated user
     */
    private UserResponse toResponse(SecUser user, boolean isOwner) {
        String decCccd  = safeDecrypt(user.getCccd());
        String decEmail = safeDecrypt(user.getEmail());
        String decPhone = safeDecrypt(user.getPhone());

        UserResponse.UserResponseBuilder builder = UserResponse.builder()
                .id(user.getId())
                .fullName(user.getFullName())
                .maskedCccd(maskingService.maskCCCD(decCccd))
                .maskedEmail(maskingService.maskEmail(decEmail))
                .maskedPhone(maskingService.maskPhone(decPhone))
                .role(user.getRole() != null ? user.getRole().getName().name() : null)
                .isOwner(isOwner);

        if (isOwner) {
            // Owner sees their own cleartext data
            builder.cccd(decCccd)
                   .email(decEmail)
                   .phone(decPhone);
        }
        // Non-owners: email/cccd/phone remain null in the response

        return builder.build();
    }

    /** Maps entity → masked-only response (no owner check). Used by saveUser. */
    private UserResponse toMaskedResponse(SecUser user, boolean isOwner) {
        return toResponse(user, isOwner);
    }

    /** Extracts the encrypted email (= username) from the current Authentication. */
    private String extractEncryptedEmail(Authentication auth) {
        if (auth == null || auth.getPrincipal() == null) return "";
        if (auth.getPrincipal() instanceof SecUser secUser) {
            return secUser.getEmail(); // encrypted email
        }
        return auth.getName(); // fallback: username from token
    }

    /** Null-safe decryption: returns null if input is null to avoid NPE */
    private String safeDecrypt(String cipherText) {
        return cipherText != null ? aesService.decrypt(cipherText) : null;
    }
}
