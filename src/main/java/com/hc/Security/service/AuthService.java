package com.hc.Security.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import com.hc.Security.dto.LoginResponse;
import com.hc.Security.repository.UserDAO;
import com.hc.Security.security.jwt.JwtTokenProvider;


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

    public LoginResponse login(String username, String password) {
        try {
            Authentication auth = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password));
            String token = tokenProvider.generateToken(auth);
            String refreshToken = refreshTokenService.create(userDAO.findByUsername(username).get().getId());
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
            System.out.println("Authentication failed for user: " + username + " - " + e.getMessage());
            throw new RuntimeException("Invalid username or password");
        }
    }

    public String logout(String authorizationHeader, String refreshToken) {

        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            String token = authorizationHeader.substring(7);
            long expiryTime = tokenProvider.getExpiration(token);
            blacklistService.blacklist(token, expiryTime);
        }

        if (refreshToken != null) {
            refreshTokenService.revokeToken(refreshToken);
        }

        SecurityContextHolder.clearContext();
        return "Logout successful";
    }

}
