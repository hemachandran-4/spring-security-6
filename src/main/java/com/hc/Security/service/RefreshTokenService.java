package com.hc.Security.service;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.DigestUtils;

import com.hc.Security.dto.LoginResponse;
import com.hc.Security.entity.RefreshToken;
import com.hc.Security.entity.User;
import com.hc.Security.repository.RefreshTokenDAO;
import com.hc.Security.repository.UserDAO;
import com.hc.Security.security.CustomUserDetailsService;
import com.hc.Security.security.jwt.JwtTokenProvider;

@Service
public class RefreshTokenService {

    private final Logger LOGGER = LoggerFactory.getLogger(RefreshTokenService.class);

    private final String SECRET_SALT = "SomeSecretSaltValue";

    private static final long REFRESH_TOKEN_TTL_DAYS = 7;

    private RefreshTokenDAO refreshTokenDAO;

    private final UserDAO userDAO;

    private final JwtTokenProvider tokenProvider;

    private final CustomUserDetailsService customUserDetailsService;

    public RefreshTokenService(
            RefreshTokenDAO refreshTokenDAO,
            UserDAO userDAO,
            JwtTokenProvider tokenProvider,
            CustomUserDetailsService customUserDetailsService) {
        this.refreshTokenDAO = refreshTokenDAO;
        this.userDAO = userDAO;
        this.tokenProvider = tokenProvider;
        this.customUserDetailsService = customUserDetailsService;
    }

    public String create(Long userId, String fingerprint) {

        String rawToken = UUID.randomUUID().toString();
        String hashedToken = hash(rawToken);

        RefreshToken token = new RefreshToken();
        token.setUserId(userId);
        token.setTokenHash(hashedToken);
        token.setFingerprintHash(hash(fingerprint));
        token.setExpiresAt(Instant.now().plusMillis(REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000));
        token.setRevoked(false);
        token.setCreatedAt(Instant.now());

        refreshTokenDAO.save(token);

        return rawToken;
    }

    public RefreshToken validateRefreshToken(String rawToken, String fingerprint) {
        String hashedToken = hash(rawToken);
        RefreshToken token = refreshTokenDAO.findByTokenHashAndRevokedFalse(hashedToken);
        
        if (token == null) {
            throw new RuntimeException("Invalid refresh token");
        }

        if (token.getExpiresAt().isBefore(Instant.now())) {
            throw new RuntimeException("Refresh token expired");
        }

        if (!token.getFingerprintHash().equals(hash(fingerprint))){
            throw new RuntimeException("Fingerprint mismatch");
        }

        return token;
    }

    @Transactional
    public String rotateToken(String oldToken, String fingerprint) {
        // Revoke old token
        RefreshToken oldRefreshToken = validateRefreshToken(oldToken, fingerprint);
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

    public Long getUserIdFromToken(String rawToken) {
        RefreshToken tokenHash = refreshTokenDAO.findByTokenHash(hash(rawToken));
        return tokenHash != null ? tokenHash.getUserId() : null;
    }

    private String hash(String token) {
        return DigestUtils.md5DigestAsHex(
                (token + SECRET_SALT).getBytes(StandardCharsets.UTF_8));
    }

    public LoginResponse refreshToken(String oldToken, String fingerprint) {

        String newRefreshToken = rotateToken(oldToken, fingerprint);

        Long userId = getUserIdFromToken(newRefreshToken);

        if (userId == null) {
            throw new RuntimeException("Invalid refresh token");
        }

        User user = userDAO.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));

        // check user status if needed

        UserDetails userDetails = customUserDetailsService
                .loadUserByUsername(user.getUsername());

        Authentication auth = new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities());
        String token = tokenProvider.generateToken(auth);

        return new LoginResponse(
                token,
                newRefreshToken,
                "Bearer",
                3600,
                auth.getName(),
                auth.getAuthorities().stream().map(a -> a.getAuthority()).toList());

    }
}
