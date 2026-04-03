package com.minh.data_masking.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "sec_users")
public class SecUser implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "sec_users_seq")
    @SequenceGenerator(name = "sec_users_seq", sequenceName = "sec_users_seq", allocationSize = 1)
    private Long id;

    @Column(name = "full_name", nullable = false, length = 200)
    private String fullName;

    /** BCrypt-hashed password */
    @Column(name = "password", nullable = false, length = 100)
    private String password;

    /** AES-encrypted + Base64 encoded ciphertext */
    @Column(name = "cccd", nullable = false, length = 500)
    private String cccd;

    /** AES-encrypted + Base64 encoded ciphertext – also used as login identifier */
    @Column(name = "email", nullable = false, unique = true, length = 500)
    private String email;

    /** AES-encrypted + Base64 encoded ciphertext */
    @Column(name = "phone", length = 500)
    private String phone;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "role_id", nullable = false)
    private Role role;

    // -------------------------------------------------------------------------
    // UserDetails contract
    // -------------------------------------------------------------------------

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.getName().name()));
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired()     { return true; }

    @Override
    public boolean isAccountNonLocked()      { return true; }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled()               { return true; }

}
