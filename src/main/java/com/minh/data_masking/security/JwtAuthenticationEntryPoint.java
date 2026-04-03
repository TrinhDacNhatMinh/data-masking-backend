package com.minh.data_masking.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;

/**
 * Handles 401 Unauthorized errors.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException
    ) throws IOException {
        log.warn("Unauthorized access attempt to [{}]: {}", request.getRequestURI(), authException.getMessage());

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        String escapedMessage = authException.getMessage() != null 
                ? authException.getMessage().replace("\"", "\\\"") 
                : "Unauthorized";
                
        String json = String.format(
            "{\"status\": 401, \"error\": \"Unauthorized\", \"message\": \"%s\", \"path\": \"%s\", \"timestamp\": \"%s\"}",
            escapedMessage,
            request.getRequestURI(),
            Instant.now().toString()
        );

        response.getWriter().write(json);
    }
}
