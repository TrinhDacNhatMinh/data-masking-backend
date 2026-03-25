package com.minh.data_masking.repository;

import com.minh.data_masking.model.SecUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<SecUser, Long> {
}
