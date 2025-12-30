package com.hc.Security.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.hc.Security.entity.TokenBlacklist;

public interface BlackListDAO extends JpaRepository<TokenBlacklist, String> {
    void deleteByTokenHash(String tokenHash);
}
