package com.hydrogrid.auth.util;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;
import java.util.UUID;


@Component
public class JwtUtil {

    private final String SECRET = "my-super-secret-key-my-super-secret-key";
    private final long ACCESS_EXPIRATION = 1000 * 60 * 15;
    private final long REFRESH_EXPIRATION = 1000L * 60 * 60 * 24 * 7;

    private Key getKey() {
        return Keys.hmacShaKeyFor(SECRET.getBytes());
    }

    @Value("${jwt.access-secret}")
    private String accessSecret;

    @Value("${jwt.refresh-secret}")
    private String refreshSecret;

    //  Access key
    private SecretKey getAccessKey() {
        return Keys.hmacShaKeyFor(accessSecret.getBytes());
    }

    //  Refresh key
    private SecretKey getRefreshKey() {
        return Keys.hmacShaKeyFor(refreshSecret.getBytes());
    }

    // ACCESS TOKEN
    public String generateAccessToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 15 * 60 * 1000))
                .signWith(getAccessKey())
                .compact();
    }

    // REFRESH TOKEN
    public String generateRefreshToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setId(UUID.randomUUID().toString())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 7L * 24 * 60 * 60 * 1000))
                .signWith(getRefreshKey())
                .compact();
    }

    // VALIDATE TOKEN
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getKey())
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }

    // EXTRACT USERNAME
    public String extractUsernameFromAccessToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getAccessKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public String extractUsernameFromRefreshToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getRefreshKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }



    //VALIDATE REFRESH TOKEN
    public boolean validateRefreshToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getRefreshKey()) // 🔥 different key
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    //VALIDATE ACCESS TOKEN
    public boolean validateAccessToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getAccessKey())
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
