package com.minh.data_masking.service;

import com.minh.data_masking.dto.auth.JwtResponse;
import com.minh.data_masking.dto.auth.LoginRequest;
import com.minh.data_masking.dto.auth.MessageResponse;
import com.minh.data_masking.dto.auth.RegisterRequest;
import com.minh.data_masking.model.ERole;
import com.minh.data_masking.model.Role;
import com.minh.data_masking.model.SecUser;
import com.minh.data_masking.repository.RoleRepository;
import com.minh.data_masking.repository.SecUserRepository;
import com.minh.data_masking.security.JwtUtil;
import com.minh.data_masking.util.AesService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final SecUserRepository secUserRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AesService aesService;
    private final JwtUtil jwtUtil;

    // ──────────────────────────────────────────────────────────────────────────
    // Register
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Registers a new user with ROLE_USER by default.
     *
     * @param request RegisterRequest with plaintext fields
     * @return MessageResponse indicating success
     * @throws IllegalArgumentException if email is already taken
     */
    @Transactional
    public MessageResponse register(RegisterRequest request) {
        // 1. Encrypt email first to check for duplicates in DB (all emails stored as ciphertext)
        String encryptedEmail = aesService.encrypt(request.email());

        if (secUserRepository.existsByEmail(encryptedEmail)) {
            throw new IllegalArgumentException("Email is already registered");
        }

        // 2. Fetch default role (ROLE_USER must exist in DB)
        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                .orElseThrow(() -> new IllegalStateException(
                        "ROLE_USER not found in database. Please seed the roles table."));

        // 3. Build user entity – BCrypt password, AES-encrypt sensitive fields
        SecUser newUser = SecUser.builder()
                .fullName(request.fullName())
                .password(passwordEncoder.encode(request.password()))  // BCrypt
                .email(encryptedEmail)                                  // AES ciphertext
                .cccd(aesService.encrypt(request.cccd()))               // AES ciphertext
                .phone(aesService.encrypt(request.phone()))             // AES ciphertext
                .role(userRole)
                .build();

        secUserRepository.save(newUser);
        log.info("New user registered: id={}", newUser.getId());

        return new MessageResponse("User registered successfully");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Login
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Authenticates a user and returns a JWT token.
     *
     * @param request LoginRequest with plaintext email and password
     * @return JwtResponse containing the signed JWT
     * @throws org.springframework.security.core.AuthenticationException on bad credentials
     */
    public JwtResponse login(LoginRequest request) {
        // 1. Encrypt email – loadUserByUsername expects encrypted email (DB stored format)
        String encryptedEmail = aesService.encrypt(request.email());

        // 2. Delegate to AuthenticationManager: internally calls loadUserByUsername(encryptedEmail)
        //    then verifies BCrypt password
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(encryptedEmail, request.password())
        );

        // 3. Extract UserDetails from the authenticated principal
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        // 4. Generate JWT
        String jwt = jwtUtil.generateToken(userDetails);

        // 5. Extract role for response (client may need it for UI routing)
        String role = userDetails.getAuthorities().stream()
                .findFirst()
                .map(a -> a.getAuthority())
                .orElse("ROLE_USER");

        log.info("User logged in successfully");
        return new JwtResponse(jwt, request.email(), role);  // return plaintext email to client
    }
}
