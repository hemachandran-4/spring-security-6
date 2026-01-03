package com.hc.Security.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.hc.Security.dto.LoginRequest;
import com.hc.Security.dto.LoginResponse;
import com.hc.Security.entity.Role;
import com.hc.Security.entity.User;
import com.hc.Security.repository.RoleDAO;
import com.hc.Security.repository.UserDAO;
import com.hc.Security.security.CustomUserDetailsService;
import com.hc.Security.security.jwt.JwtTokenProvider;


@Service
public class AuthService {

    private final Logger LOGGER = LoggerFactory.getLogger(AuthService.class);

    private final AuthenticationManager authManager;
    private final JwtTokenProvider tokenProvider;
    private final UserDAO userDAO;
    private final RoleDAO roleDAO;
    private final PasswordEncoder passwordEncoder;
    private final BlackListService blacklistService;
    private final RefreshTokenService refreshTokenService;
    private final CustomUserDetailsService customUserDetailsService;

    public AuthService(AuthenticationManager authManager,
                       JwtTokenProvider tokenProvider,
                       UserDAO userDAO,
                       PasswordEncoder passwordEncoder,
                       RoleDAO roleDAO,
                       BlackListService blacklistService,
                       RefreshTokenService refreshTokenService,
                       CustomUserDetailsService customUserDetailsService) {
        this.authManager = authManager;
        this.tokenProvider = tokenProvider;
        this.userDAO = userDAO;
        this.passwordEncoder = passwordEncoder;
        this.roleDAO = roleDAO;
        this.blacklistService = blacklistService;
        this.refreshTokenService = refreshTokenService;
        this.customUserDetailsService = customUserDetailsService;
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

    public String register(LoginRequest request) {

        if (userDAO.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username already exists");
        }
        Long roleId = null;
        String roleName = "ROLE_USER";
        if (request.getLoginType() != null && request.getLoginType() == 1) {
            roleName = "ROLE_ADMIN";
        }

        if (roleDAO.existsByName(roleName)) {
            roleId = roleDAO.findByName(roleName).get().getId();
        } else {
            Role role = new Role();
            role.setName(roleName);
            role = roleDAO.save(role);
            roleId = role.getId();
        }
        
        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setRoleId(roleId);

        userDAO.save(user);
        return "User registered successfully";
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

    public LoginResponse refreshToken(String oldToken) {

        String newRefreshToken = refreshTokenService.rotateToken(oldToken);

        Long userId = refreshTokenService.getUserIfFromToken(newRefreshToken);

        if(userId == null) {
            throw new RuntimeException("Invalid refresh token");
        }

        User user = userDAO.findById(userId).orElseThrow(() ->
            new RuntimeException("User not found"));

        // check user status id needed

        UserDetails userDetails = customUserDetailsService
        .loadUserByUsername(user.getUsername());

        Authentication auth = new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
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
