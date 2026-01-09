package com.hc.Security.service;

import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import com.hc.Security.dto.LoginRequest;
import com.hc.Security.dto.LoginResponse;
import com.hc.Security.repository.UserDAO;
import com.hc.Security.security.jwt.JwtTokenProvider;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


@Service
public class AuthService {

    private final Logger LOGGER = LoggerFactory.getLogger(AuthService.class);

    private final AuthenticationManager authManager;

    private final JwtTokenProvider tokenProvider;

    private final UserDAO userDAO;

    private final BlackListService blacklistService;
    
    private final RefreshTokenService refreshTokenService;

    public AuthService(AuthenticationManager authManager,
                       JwtTokenProvider tokenProvider,
                       UserDAO userDAO,
                       BlackListService blacklistService,
                       RefreshTokenService refreshTokenService) {
        this.authManager = authManager;
        this.tokenProvider = tokenProvider;
        this.userDAO = userDAO;
        this.blacklistService = blacklistService;
        this.refreshTokenService = refreshTokenService;
    }

    public LoginResponse login(LoginRequest request,
        HttpServletRequest httpRequest, HttpServletResponse httpResponse) {
        try {
            Authentication auth = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
            String token = tokenProvider.generateToken(auth);
            String fingerprint = extractFingerprint(httpRequest);
            if (fingerprint == null) {
                fingerprint = UUID.randomUUID().toString();
                httpResponse.addHeader(
                        "Set-Cookie",
                        "FPID=" + fingerprint +
                                "; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000");
            }
            String refreshToken = refreshTokenService
                    .create(userDAO.findByUsername(request.getUsername()).get().getId(), fingerprint);
            return new LoginResponse(
                    token,
                    refreshToken,
                    "Bearer",
                    3600,
                    auth.getName(),
                    auth.getAuthorities()
                            .stream()
                            .map(a -> a.getAuthority())
                            .toList());
        } catch (Exception e) {
            System.out.println("Authentication failed for user: " + request.getUsername() + " - " + e.getMessage());
            throw new RuntimeException("Invalid username or password");
        }
    }

    public String logout(String authorizationHeader,
            String refreshToken, HttpServletResponse httpResponse) {

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7);
            long expiryTime = tokenProvider.getExpiration(token);
            blacklistService.blacklist(token, expiryTime);
        }

        if (refreshToken != null) {
            refreshTokenService.revokeToken(refreshToken);
        }
        
        deleteFingerprintCookie(httpResponse);

        SecurityContextHolder.clearContext();
        return "Logout successful";
    }

    private String extractFingerprint(HttpServletRequest request) {
        if (request.getCookies() == null)
            return null;

        for (Cookie cookie : request.getCookies()) {
            if ("FPID".equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    private void deleteFingerprintCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie("FPID", "");
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        cookie.setSecure(false); // false for localhost testing, true for production
        cookie.setMaxAge(0);

        response.addCookie(cookie);
    }
}
