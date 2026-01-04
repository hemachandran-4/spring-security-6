package com.hc.Security.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.hc.Security.dto.LoginRequest;
import com.hc.Security.entity.Role;
import com.hc.Security.entity.User;
import com.hc.Security.repository.RoleDAO;
import com.hc.Security.repository.UserDAO;

@Service
public class UserService {
    
    private final UserDAO userDAO;
    private final RoleDAO roleDAO;
    private final PasswordEncoder passwordEncoder;

    public UserService(
            UserDAO userDAO,
            RoleDAO roleDAO,
            PasswordEncoder passwordEncoder) {
        this.userDAO = userDAO;
        this.roleDAO = roleDAO;
        this.passwordEncoder = passwordEncoder;
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
