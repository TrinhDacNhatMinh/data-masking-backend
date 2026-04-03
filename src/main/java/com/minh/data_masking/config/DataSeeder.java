package com.minh.data_masking.config;

import com.minh.data_masking.model.ERole;
import com.minh.data_masking.model.Role;
import com.minh.data_masking.model.SecUser;
import com.minh.data_masking.repository.RoleRepository;
import com.minh.data_masking.repository.SecUserRepository;
import com.minh.data_masking.util.AesService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Chạy một lần khi ứng dụng khởi động.
 * – Tạo ROLE_USER và ROLE_ADMIN nếu chưa tồn tại.
 * – Tạo tài khoản admin mặc định nếu chưa có.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class DataSeeder implements CommandLineRunner {

    private final RoleRepository    roleRepository;
    private final SecUserRepository secUserRepository;
    private final PasswordEncoder   passwordEncoder;
    private final AesService        aesService;

    // ── Thông tin admin mặc định ─────────────────────────────────────────────
    private static final String ADMIN_FULL_NAME = "System Administrator";
    private static final String ADMIN_EMAIL     = "admin@gmail.com";
    private static final String ADMIN_PASSWORD  = "Admin@1234";
    private static final String ADMIN_CCCD      = "000000000000";   // placeholder
    private static final String ADMIN_PHONE     = "0000000000";     // placeholder
    // ─────────────────────────────────────────────────────────────────────────

    @Override
    @Transactional
    public void run(String... args) {
        seedRoles();
        seedAdminAccount();
    }

    // ── Seed roles ────────────────────────────────────────────────────────────

    private void seedRoles() {
        for (ERole eRole : ERole.values()) {
            if (roleRepository.findByName(eRole).isEmpty()) {
                roleRepository.save(Role.builder().name(eRole).build());
                log.info("[Seeder] Created role: {}", eRole);
            } else {
                log.debug("[Seeder] Role already exists, skipping: {}", eRole);
            }
        }
    }

    // ── Seed admin account ────────────────────────────────────────────────────

    private void seedAdminAccount() {
        String encryptedAdminEmail = aesService.encrypt(ADMIN_EMAIL);

        if (secUserRepository.existsByEmail(encryptedAdminEmail)) {
            log.debug("[Seeder] Admin account already exists, skipping.");
            return;
        }

        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                .orElseThrow(() -> new IllegalStateException(
                        "[Seeder] ROLE_ADMIN not found – seedRoles() must run first."));

        SecUser admin = SecUser.builder()
                .fullName(ADMIN_FULL_NAME)
                .email(encryptedAdminEmail)                         // AES ciphertext
                .password(passwordEncoder.encode(ADMIN_PASSWORD))   // BCrypt hash
                .cccd(aesService.encrypt(ADMIN_CCCD))               // AES ciphertext
                .phone(aesService.encrypt(ADMIN_PHONE))             // AES ciphertext
                .role(adminRole)
                .build();

        secUserRepository.save(admin);
        log.info("[Seeder] Admin account created. Email: {}", ADMIN_EMAIL);
        log.warn("[Seeder] *** PLEASE CHANGE THE DEFAULT ADMIN PASSWORD IN PRODUCTION! ***");
    }
}
