package com.minh.data_masking.service;

import com.minh.data_masking.repository.SecUserRepository;
import com.minh.data_masking.util.AesService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class SecUserDetailsService implements UserDetailsService {

    private final SecUserRepository secUserRepository;
    private final AesService aesService;

    /**
     * Loads a user by their AES-encrypted email.
     *
     * @param encryptedEmail AES-encrypted + Base64 email (callers must encrypt before invoking)
     * @throws UsernameNotFoundException if no user found
     */
    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String encryptedEmail) throws UsernameNotFoundException {
        return secUserRepository.findByEmail(encryptedEmail)
                .orElseThrow(() -> {
                    log.warn("User not found for encrypted email lookup");
                    return new UsernameNotFoundException("User not found");
                });
    }
}
