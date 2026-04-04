package com.minh.data_masking.util;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

@Service
public class RsaService {

    private BigInteger n; // Khóa công khai (Modulus)
    private BigInteger e; // Khóa công khai (Exponent)
    private BigInteger d; // Khóa bí mật (Private Exponent)

    /**
     * Tự code chay thuật toán sinh khóa RSA 2048-bit
     */
    @PostConstruct
    public void initKeys() {
        SecureRandom random = new SecureRandom();
        int bitLength = 2048; // Độ dài bit của N

        // 1. Sinh 2 số nguyên tố lớn p và q (mỗi số 1024 bit)
        BigInteger p = new BigInteger(bitLength / 2, 100, random);
        BigInteger q = new BigInteger(bitLength / 2, 100, random);

        // 2. Tính n = p * q
        this.n = p.multiply(q);

        // 3. Tính hàm phi Euler: phi(n) = (p-1) * (q-1)
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        // 4. Chọn e (Thường dùng số Fermat thứ 4 cho nhanh và phổ biến)
        this.e = new BigInteger("65537");

        // Đảm bảo e và phi(n) là nguyên tố cùng nhau (ƯCLN = 1)
        while (phi.gcd(this.e).compareTo(BigInteger.ONE) > 0 && this.e.compareTo(phi) < 0) {
            this.e = this.e.add(BigInteger.ONE);
        }

        // 5. Tính khóa bí mật d (Nghịch đảo modulo của e theo modulo phi)
        this.d = this.e.modInverse(phi);

        System.out.println("Đã sinh xong khóa RSA Code Chay!");
    }

    /**
     * Thay vì trả về Base64 chuẩn bị sẵn, ta phải trả về trực tiếp 2 số N và E (dạng Hex)
     * để Frontend tự nhặt lấy và tự tính toán.
     */
    public Map<String, String> getRawPublicKey() {
        Map<String, String> keyMap = new HashMap<>();
        keyMap.put("n", this.n.toString(16)); // Trả về dạng Hexa
        keyMap.put("e", this.e.toString(16)); // Trả về dạng Hexa
        return keyMap;
    }

    /**
     * Code chay hàm giải mã RSA: m = c^d mod n
     * @param encryptedHex Chuỗi mã hóa dạng Hexa do Frontend gửi lên
     * @return Chuỗi chữ rõ (Plaintext)
     */
    public String decrypt(String encryptedHex) {
        // 1. Biến chuỗi Hexa thành con số BigInteger (Bản rõ C)
        BigInteger c = new BigInteger(encryptedHex, 16);

        // 2. Thực hiện phép toán giải mã cốt lõi: m = c^d mod n
        BigInteger m = c.modPow(this.d, this.n);

        // 3. Biến con số m thành mảng byte, rồi ép kiểu về String
        return new String(m.toByteArray());
    }

    /**
     * Code chay hàm mã hóa RSA: c = m^e mod n (Để test)
     */
    public String encrypt(String plainText) {
        BigInteger m = new BigInteger(1, plainText.getBytes());
        BigInteger c = m.modPow(this.e, this.n);
        return c.toString(16); // Trả về dạng Hexa
    }
}