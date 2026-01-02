package com.hc.Security.repository;

import java.time.Instant;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.hc.Security.entity.RefreshToken;

public interface RefreshTokenDAO extends JpaRepository<RefreshToken, Long> {

    RefreshToken findByToken(String token);

    @Modifying
    @Query("""
        DELETE FROM RefreshToken r
        WHERE r.expiry < :now
           OR r.revoked = true
    """)
    int deleteExpiredOrRevoked(@Param("now") Instant now);
    
}
