package com.hc.Security.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.hc.Security.entity.User;

public interface UserDAO extends JpaRepository<User, Long>{

    boolean existsByUsername(String username);

    Optional<User> findByUsername(String username);
    
}
