package com.hc.Security.service;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.DigestUtils;

import com.hc.Security.entity.RefreshToken;
import com.hc.Security.repository.RefreshTokenDAO;

@Service
public class RefreshTokenService {

    private final Logger LOGGER = LoggerFactory.getLogger(RefreshTokenService.class);

    private final String SECRET_SALT = "SomeSecretSaltValue";

    private static final long REFRESH_TOKEN_TTL_DAYS = 7;

    private RefreshTokenDAO refreshTokenDAO;

    public RefreshTokenService(RefreshTokenDAO refreshTokenDAO) {
        this.refreshTokenDAO = refreshTokenDAO;
    }

    public String create(Long userId) {

        String rawToken = UUID.randomUUID().toString();
        String hashedToken = hash(rawToken);

        RefreshToken token = new RefreshToken();
        token.setUserId(userId);
        token.setTokenHash(hashedToken);
        token.setExpiresAt(Instant.now().plusMillis(REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000));
        token.setRevoked(false);
        token.setCreatedAt(Instant.now());

        refreshTokenDAO.save(token);

        return rawToken;
    }

    public RefreshToken validateRefreshToken(String rawToken) {
        String hashedToken = hash(rawToken);
        RefreshToken token = refreshTokenDAO.findByTokenHashAndRevokedFalse(hashedToken);
        
        if (token == null) {
            throw new RuntimeException("Invalid refresh token");
        }

        if (token.getExpiresAt().isBefore(Instant.now())) {
            throw new RuntimeException("Refresh token expired");
        }

        return token;
    }

    @Transactional
    public String rotateToken(String oldToken) {
        // Revoke old token
        RefreshToken oldRefreshToken = validateRefreshToken(oldToken);
        oldRefreshToken.setRevoked(true);
        oldRefreshToken.setRevokedAt(Instant.now());
        
        // Create new token
        String rawNewToken = UUID.randomUUID().toString();
        String hashedToken = hash(rawNewToken);
        oldRefreshToken.setReplacedByTokenHash(hashedToken);

        RefreshToken newRefreshToken = new RefreshToken();
        newRefreshToken.setUserId(oldRefreshToken.getUserId());
        newRefreshToken.setTokenHash(hashedToken);
        newRefreshToken.setExpiresAt(Instant.now().plusMillis(REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000));
        newRefreshToken.setRevoked(false);
        newRefreshToken.setCreatedAt(Instant.now());

        refreshTokenDAO.saveAll(List.of(oldRefreshToken, newRefreshToken));

        return rawNewToken;
    }

    public void revokeToken(String rawToken) {
        String hash = hash(rawToken);

        RefreshToken refreshToken = refreshTokenDAO.findByTokenHashAndRevokedFalse(hash);
        if (refreshToken != null) {
            refreshToken.setRevoked(true);
            refreshToken.setRevokedAt(Instant.now());
            refreshTokenDAO.save(refreshToken);
        }
    }

    public void revokeAllTokens(Long userId) {
        List<RefreshToken> tokens = refreshTokenDAO.findAllByUserIdAndRevokedFalse(userId);

        tokens.forEach(token -> {
            token.setRevoked(true);
            token.setRevokedAt(Instant.now());
        });

        refreshTokenDAO.saveAll(tokens);
    }

    public Long getUserIfFromToken(String rawToken) {
        RefreshToken tokenHash = refreshTokenDAO.findByTokenHash(hash(rawToken));
        return tokenHash != null ? tokenHash.getUserId() : null;
    }

    private String hash(String token) {
        return DigestUtils.md5DigestAsHex(
                (token + SECRET_SALT).getBytes(StandardCharsets.UTF_8));
    }
}
