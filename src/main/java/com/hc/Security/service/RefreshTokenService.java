package com.hc.Security.service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.hc.Security.entity.RefreshToken;
import com.hc.Security.repository.RefreshTokenDAO;

@Service
public class RefreshTokenService {

    private static final long REFRESH_TOKEN_TTL_DAYS = 7;

    private RefreshTokenDAO refreshTokenDAO;

    public RefreshTokenService(RefreshTokenDAO refreshTokenDAO) {
        this.refreshTokenDAO = refreshTokenDAO;
    }

    public RefreshToken create(String username, String password) {
        RefreshToken token = new RefreshToken();
        token.setToken(UUID.randomUUID().toString());
        token.setUsername(username);
        token.setPassword(password);
        token.setExpiry(Instant.now().plus(REFRESH_TOKEN_TTL_DAYS, ChronoUnit.DAYS));
        token.setRevoked(false);
        return refreshTokenDAO.save(token);
    }

    public RefreshToken validate(String tokenValue) {
        RefreshToken token = refreshTokenDAO.findByToken(tokenValue);
        if(token == null) {
            throw new RuntimeException("Invalid refresh token");
        }

        if (token.isRevoked() || token.getExpiry().isBefore(Instant.now())) {
            throw new RuntimeException("Refresh token expired or revoked");
        }

        return token;
    }

    public void revoke(RefreshToken token) {
        token.setRevoked(true);
        refreshTokenDAO.save(token);
    }
}
