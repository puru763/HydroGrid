package com.hydrogrid.auth.service;



import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class TokenBlacklistService {

    private final StringRedisTemplate redisTemplate;

    public TokenBlacklistService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    // Add token to Redis
    public void blacklistToken(String token, long expiryMillis) {
        redisTemplate.opsForValue()
                .set(token, "blacklisted", expiryMillis, TimeUnit.MILLISECONDS);
    }

    // Check token
    public boolean isBlacklisted(String token) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(token));
    }
}