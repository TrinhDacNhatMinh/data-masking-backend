package com.minh.data_masking.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.minh.data_masking.dto.auth.*;
import com.minh.data_masking.model.ERole;
import com.minh.data_masking.model.Role;
import com.minh.data_masking.model.SecUser;
import com.minh.data_masking.repository.RoleRepository;
import com.minh.data_masking.repository.SecUserRepository;
import com.minh.data_masking.security.JwtUtil;
import com.minh.data_masking.util.AesService;
import com.minh.data_masking.util.RsaService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

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

    // Thêm các dependency mới cho Hybrid Encryption
    private final RsaService rsaService;
    private final ObjectMapper objectMapper;

    // ──────────────────────────────────────────────────────────────────────────
    // Register Standard
    // ──────────────────────────────────────────────────────────────────────────

    @Transactional
    public MessageResponse register(RegisterRequest request) {
        String encryptedEmail = aesService.encrypt(request.email());

        if (secUserRepository.existsByEmail(encryptedEmail)) {
            throw new IllegalArgumentException("Email is already registered");
        }

        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                .orElseThrow(() -> new IllegalStateException(
                        "ROLE_USER not found in database. Please seed the roles table."));

        SecUser newUser = SecUser.builder()
                .fullName(request.fullName())
                .password(passwordEncoder.encode(request.password()))
                .email(encryptedEmail)
                .cccd(aesService.encrypt(request.cccd()))
                .phone(aesService.encrypt(request.phone()))
                .role(userRole)
                .build();

        secUserRepository.save(newUser);
        log.info("New user registered: id={}", newUser.getId());

        return new MessageResponse("User registered successfully");
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Register Secure (Hybrid Encryption - RSA Code Chay + AES)
    // ──────────────────────────────────────────────────────────────────────────

    @Transactional
    public MessageResponse registerSecure(EncryptedRegisterRequest encryptedRequest) throws Exception {
        // 1. Dùng RSA Code Chay giải mã chuỗi Hexa để lấy lại Session Key
        String sessionKey = rsaService.decrypt(encryptedRequest.getEncryptedSessionKey());

        // 2. Dùng Session Key giải mã Payload AES để lấy lại chuỗi JSON
        String decryptedJson = decryptAesSession(encryptedRequest.getEncryptedPayload(), sessionKey);

        // 3. Ép chuỗi JSON thu được về record RegisterRequest
        RegisterRequest registerRequest = objectMapper.readValue(decryptedJson, RegisterRequest.class);

        // 4. Gọi lại hàm register cũ để thực hiện mã hóa AES Code chay và lưu DB
        return register(registerRequest);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Login Standard
    // ──────────────────────────────────────────────────────────────────────────

    public JwtResponse login(LoginRequest request) {
        String encryptedEmail = aesService.encrypt(request.email());

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(encryptedEmail, request.password())
        );

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String jwt = jwtUtil.generateToken(userDetails);
        String role = userDetails.getAuthorities().stream()
                .findFirst()
                .map(a -> a.getAuthority())
                .orElse("ROLE_USER");

        log.info("User logged in successfully");
        return new JwtResponse(jwt, request.email(), role);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Login Secure (Hybrid Encryption - RSA Code Chay + AES)
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Luồng đăng nhập bảo mật: Giải mã RSA Code Chay -> Giải mã AES Session -> Authenticate
     */
    public JwtResponse loginSecure(EncryptedLoginRequest encryptedRequest) throws Exception {
        // 1. Dùng RSA Code Chay giải mã chuỗi Hexa để lấy lại Session Key (Khóa AES tạm thời)
        // Vì RSA code chay trả về chuỗi Hexa nên ta dùng rsaService.decrypt()
        String sessionKey = rsaService.decrypt(encryptedRequest.getEncryptedSessionKey());

        // 2. Dùng Session Key đó để giải mã Payload (Email/Password)
        // Lưu ý: Dùng AES thư viện chuẩn của Java để giải mã cục Session này cho tương thích với CryptoJS bên Frontend
        String decryptedJson = decryptAesSession(encryptedRequest.getEncryptedPayload(), sessionKey);

        // 3. Ép chuỗi JSON thu được về record LoginRequest
        LoginRequest loginRequest = objectMapper.readValue(decryptedJson, LoginRequest.class);

        // 4. Gọi lại hàm login cũ để thực hiện xác thực JWT như bình thường
        return login(loginRequest);
    }

    /**
     * Hàm phụ trợ giải mã AES cho phiên làm việc (Session)
     * Dùng thuật toán AES/ECB/PKCS5Padding để khớp với frontend (ví dụ CryptoJS)
     */
    private String decryptAesSession(String encryptedData, String key) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decodedBytes = Base64.getDecoder().decode(encryptedData);
        return new String(cipher.doFinal(decodedBytes));
    }
}