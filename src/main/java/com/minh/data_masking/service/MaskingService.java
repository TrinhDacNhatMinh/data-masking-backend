package com.minh.data_masking.service;

import org.springframework.stereotype.Service;

@Service
public class MaskingService {

    /**
     * Masks national ID (CCCD): keeps last 4 digits, replaces the rest with '*'
     * Example: "012345678901" → "********8901"
     */
    public String maskCCCD(String cccd) {
        if (cccd == null || cccd.length() <= 4) return cccd;
        int maskLength = cccd.length() - 4;
        return "*".repeat(maskLength) + cccd.substring(maskLength);
    }

    /**
     * Masks email: keeps first 2 characters of local part + "***" + "@domain"
     * Example: "test@gmail.com" → "te***@gmail.com"
     */
    public String maskEmail(String email) {
        if (email == null || !email.contains("@")) return email;
        String[] parts = email.split("@");
        String name = parts[0];
        String domain = parts[1];
        if (name.length() <= 2) return name + "***@" + domain;
        return name.substring(0, 2) + "***@" + domain;
    }

    /**
     * Masks phone number: first 3 digits + "****" + last 3 digits
     * Example: "0971234567" → "097****567"
     */
    public String maskPhone(String phone) {
        if (phone == null || phone.length() <= 6) return phone;
        return phone.substring(0, 3) + "****" + phone.substring(phone.length() - 3);
    }

}
