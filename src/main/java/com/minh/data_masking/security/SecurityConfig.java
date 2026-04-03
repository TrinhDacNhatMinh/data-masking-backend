package com.minh.data_masking.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final UserDetailsService userDetailsService;

    // ──────────────────────────────────────────────────────────────────────────
    // Security Filter Chain
    // ──────────────────────────────────────────────────────────────────────────

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            // Disable CSRF – not needed for stateless JWT APIs
            .csrf(AbstractHttpConfigurer::disable)

            // CORS – delegate to CorsConfig (WebMvcConfigurer) already registered as a bean
            .cors(cors -> cors.configure(http))

            // Authorization rules
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()   // Public auth endpoints
                .anyRequest().authenticated()                   // All others require valid JWT
            )

            // Stateless session – Spring Security will never create an HttpSession
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )

            // Custom 401 entry point – returns JSON instead of redirect/HTML
            .exceptionHandling(ex ->
                ex.authenticationEntryPoint(jwtAuthenticationEntryPoint)
            )

            // Register JWT filter before the standard username/password filter
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Authentication Provider (DAO – loads from DB)
    // ──────────────────────────────────────────────────────────────────────────

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Shared beans
    // ──────────────────────────────────────────────────────────────────────────

    /**
     * Exposes AuthenticationManager for use in AuthService.login().
     * In Spring Security 7, retrieved via AuthenticationConfiguration (no adapter needed).
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    /**
     * BCrypt password encoder – strength 12 (good balance of security vs performance).
     * Shared across AuthService and DaoAuthenticationProvider.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
