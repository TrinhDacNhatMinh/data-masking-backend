package com.minh.data_masking.exception;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    private Map<String, Object> buildError(HttpStatus status, String message, String path) {
        Map<String, Object> error = new LinkedHashMap<>();
        error.put("timestamp", Instant.now());
        error.put("status", status.value());
        error.put("error", status.getReasonPhrase());
        error.put("message", message);
        error.put("path", path);
        return error;
    }

    // THÊM MỚI: Xử lý lỗi Sai tài khoản / mật khẩu (Mã 401)
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Map<String, Object>> handleBadCredentials(BadCredentialsException ex, HttpServletRequest request) {
        log.warn("Login failed: Bad credentials");

        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(buildError(HttpStatus.UNAUTHORIZED,
                        "Tài khoản hoặc mật khẩu không chính xác. Vui lòng thử lại!",
                        request.getRequestURI()
                ));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(
            MethodArgumentNotValidException ex, HttpServletRequest request) {

        Map<String, String> fieldErrors = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .collect(Collectors.toMap(
                        FieldError::getField,
                        f -> (f.getDefaultMessage() != null ?
                                f.getDefaultMessage() : "Invalid value"),
                        (a, b) -> b
                ));

        Map<String, Object> response =
                buildError(HttpStatus.BAD_REQUEST, "Validation failed", request.getRequestURI());

        response.put("errors", fieldErrors);

        return ResponseEntity.badRequest().body(response);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGeneric(Exception ex, HttpServletRequest request) {
        log.error("Unhandled exception: ", ex);

        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(buildError(HttpStatus.INTERNAL_SERVER_ERROR,
                        ex.getMessage(),
                        request.getRequestURI()
                ));
    }
}