package com.minh.data_masking.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "sec_users")
public class SecUser {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "sec_users_seq")
    @SequenceGenerator(name = "sec_users_seq", sequenceName = "sec_users_seq", allocationSize = 1)
    private Long id;

    @Column(name = "full_name", nullable = false, length = 200)
    private String fullName;

    // Ciphertext (AES encrypted + Base64)
    @Column(name = "cccd", nullable = false, length = 500)
    private String cccd;

    @Column(name = "email", length = 500)
    private String email;

    @Column(name = "phone", length = 500)
    private String phone;

}
