package com.minh.data_masking.controller;

import com.minh.data_masking.dto.UserRequest;
import com.minh.data_masking.dto.UserResponse;
import com.minh.data_masking.service.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    /**
     * GET /api/users/all
     * Fetches all users from DB without pagination → decrypts → applies owner-aware Data Masking.
     */
    @GetMapping("/all")
    public ResponseEntity<java.util.List<UserResponse>> getAllUser(Authentication auth) {
        return ResponseEntity.ok(userService.getUsers(auth));
    }
}