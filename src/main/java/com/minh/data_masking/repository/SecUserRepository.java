package com.minh.data_masking.repository;

import com.minh.data_masking.model.SecUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SecUserRepository extends JpaRepository<SecUser, Long> {

    /**
     * Finds a user by their AES-encrypted email.
     * @param encryptedEmail the AES-encrypted + Base64-encoded email value
     */
    Optional<SecUser> findByEmail(String encryptedEmail);

    /**
     * Checks for duplicate registration by encrypted email.
     * @param encryptedEmail the AES-encrypted + Base64-encoded email value
     */
    boolean existsByEmail(String encryptedEmail);
    
}
