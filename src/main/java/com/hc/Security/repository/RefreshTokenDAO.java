package com.hc.Security.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.hc.Security.entity.RefreshToken;

public interface RefreshTokenDAO extends JpaRepository<RefreshToken, Long> {

    RefreshToken findByToken(String token);
    
}
