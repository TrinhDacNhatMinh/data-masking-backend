package com.minh.data_masking.service;

import com.minh.data_masking.dto.UserRequest;
import com.minh.data_masking.dto.UserResponse;
import com.minh.data_masking.model.SecUser;
import com.minh.data_masking.repository.UserRepository;
import com.minh.data_masking.util.AesService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final AesService aesService;
    private final MaskingService maskingService;
    private final UserRepository userRepository;

    /**
     * Encrypts plaintext fields → saves ciphertext to DB → returns DTO (entity not exposed)
     */
    @Transactional
    public UserResponse saveUser(UserRequest request) {
        SecUser user = SecUser.builder()
                .fullName(request.fullName())
                .cccd(aesService.encrypt(request.cccd()))
                .email(aesService.encrypt(request.email()))
                .phone(aesService.encrypt(request.phone()))
                .build();
        return toResponse(userRepository.save(user));
    }

    /**
     * Fetches users from DB with pagination → decrypts → applies masking → returns DTO
     */
    @Transactional(readOnly = true)
    public Page<UserResponse> getAllUsers(Pageable pageable) {
        return userRepository.findAll(pageable)
                .map(this::toResponse);
    }

    /**
     * Maps entity → DTO: decrypts and masks each sensitive field.
     */
    private UserResponse toResponse(SecUser user) {
        String decCccd  = safeDecrypt(user.getCccd());
        String decEmail = safeDecrypt(user.getEmail());
        String decPhone = safeDecrypt(user.getPhone());

        return UserResponse.builder()
                .fullName(user.getFullName())
                .maskedCccd(maskingService.maskCCCD(decCccd))
                .maskedEmail(maskingService.maskEmail(decEmail))
                .maskedPhone(maskingService.maskPhone(decPhone))
                .build();
    }

    /** Null-safe decryption: returns null if input is null to avoid NPE */
    private String safeDecrypt(String cipherText) {
        return cipherText != null ? aesService.decrypt(cipherText) : null;
    }
    
}
