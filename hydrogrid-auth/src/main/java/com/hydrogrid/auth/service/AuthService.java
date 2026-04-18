package com.hydrogrid.auth.service;


import com.hydrogrid.auth.dto.AuthResponse;
import com.hydrogrid.auth.entity.RefreshToken;
import com.hydrogrid.auth.repository.RefreshTokenRepository;
import com.hydrogrid.auth.util.JwtUtil;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class AuthService {

    private final JwtUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;

    public AuthService(JwtUtil jwtUtil,
                       RefreshTokenRepository refreshTokenRepository) {
        this.jwtUtil = jwtUtil;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public AuthResponse refreshToken(String refreshToken) {

        // 1. Validate JWT (signature + expiry)
        if (!jwtUtil.validateRefreshToken(refreshToken)) {
            throw new RuntimeException("Invalid refresh token");
        }

        // 2. Fetch from DB
        RefreshToken tokenEntity = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new RuntimeException("Refresh token not found"));

        // 3. Check revoked / expired
        if (tokenEntity.isRevoked() ||
                tokenEntity.getExpiryDate().before(new Date())) {
            throw new RuntimeException("Refresh token expired or revoked");
        }

        // 4. Extract username
        String username = jwtUtil.extractUsernameFromRefreshToken(refreshToken);


        // 5. ROTATION → revoke old token
        tokenEntity.setRevoked(true);
        refreshTokenRepository.save(tokenEntity);

        // 6. Generate new tokens
        String newAccessToken = jwtUtil.generateAccessToken(username);
        String newRefreshToken = jwtUtil.generateRefreshToken(username);

        // 7. Save new refresh token
        RefreshToken newToken = new RefreshToken();
        newToken.setToken(newRefreshToken);
        newToken.setUsername(username);
        newToken.setRevoked(false);
        newToken.setExpiryDate(
                new Date(System.currentTimeMillis() + 7L * 24 * 60 * 60 * 1000)
        );

        refreshTokenRepository.save(newToken);

        // 8. Return ONLY access token (refresh handled via cookie)
        return new AuthResponse(newAccessToken, newRefreshToken);
    }
}