package com.hc.Security.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.hc.Security.entity.TokenBlacklist;

public interface BlackListDAO extends JpaRepository<TokenBlacklist, String> {

    void deleteByTokenHash(String tokenHash);


    @Modifying
    @Query("""
        DELETE FROM TokenBlacklist t
        WHERE t.expiresAt < :now
    """)
    int deleteExpired(@Param("now") long now);
    
}
