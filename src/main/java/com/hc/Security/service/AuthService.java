package com.hc.Security.service;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.hc.Security.dto.LoginRequest;
import com.hc.Security.dto.LoginResponse;
import com.hc.Security.entity.Role;
import com.hc.Security.entity.User;
import com.hc.Security.repository.RoleDAO;
import com.hc.Security.repository.UserDAO;
import com.hc.Security.security.jwt.JwtTokenProvider;

@Service
public class AuthService {

    private final AuthenticationManager authManager;
    private final JwtTokenProvider tokenProvider;
    private final UserDAO userDAO;
    private final RoleDAO roleDAO;
    private final PasswordEncoder passwordEncoder;

    public AuthService(AuthenticationManager authManager,
                       JwtTokenProvider tokenProvider,
                       UserDAO userDAO,
                       PasswordEncoder passwordEncoder,
                       RoleDAO roleDAO) {
        this.authManager = authManager;
        this.tokenProvider = tokenProvider;
        this.userDAO = userDAO;
        this.passwordEncoder = passwordEncoder;
        this.roleDAO = roleDAO;
    }

    public LoginResponse login(String username, String password) {
        System.out.println("Attempting to authenticate user: " + username);
        Authentication auth = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password));
        String token = tokenProvider.generateToken(auth);

        return new LoginResponse(
                token,
                "Bearer",
                3600,
                auth.getName(),
                auth.getAuthorities()
                        .stream()
                        .map(a -> a.getAuthority())
                        .toList());
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
}
