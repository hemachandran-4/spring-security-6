package com.hc.Security.security;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.hc.Security.entity.Role;
import com.hc.Security.entity.User;
import com.hc.Security.repository.RoleDAO;
import com.hc.Security.repository.UserDAO;

@Service
public class CustomUserDetailsService implements UserDetailsService{

    private final UserDAO userDAO;
    private final RoleDAO roleDAO;

    public CustomUserDetailsService(UserDAO userDAO, RoleDAO roleDAO) {
        this.userDAO = userDAO;
        this.roleDAO = roleDAO;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userDAO.findByUsername(username).orElseThrow(() -> 
            new UsernameNotFoundException("User not found with username: " + username)
        );
        Role role = roleDAO.findById(user.getRoleId()).orElseThrow(() -> 
            new UsernameNotFoundException("Role not found with id: " + user.getRoleId())
        );
        return new CustomUserDetails(user, role);
    }
    
}
