package com.hc.Security.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "token_blacklist")
public class TokenBlacklist {

    @Id
    @Column(name = "token_hash", length = 64)
    private String tokenHash;

    @Column(name = "expires_at", nullable = false)
    private Long expiresAt;

    protected TokenBlacklist() {
    }

    public TokenBlacklist(String tokenHash, Long expiresAt) {
        this.tokenHash = tokenHash;
        this.expiresAt = expiresAt;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public Long getExpiresAt() {
        return expiresAt;
    }
}