package com.hc.Security.service;

import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.hc.Security.repository.BlackListDAO;
import com.hc.Security.repository.RefreshTokenDAO;

@Service
public class TokenCleanupService {
    
    private final Logger logger = LoggerFactory.getLogger(TokenCleanupService.class);

    private final BlackListDAO blackListDAO;
    private final RefreshTokenDAO refreshTokenDAO;

    public TokenCleanupService(BlackListDAO blackListDAO,
                               RefreshTokenDAO refreshTokenDAO) {
        this.blackListDAO = blackListDAO;
        this.refreshTokenDAO = refreshTokenDAO;
    }

    @Transactional
    @Scheduled(fixedRate = 360000) // every minute
    public void cleanupExpiredTokens() {

        long now = System.currentTimeMillis();

        int deletedBlacklist =
                blackListDAO.deleteExpired(now);

        int deletedRefreshTokens =
                refreshTokenDAO.deleteExpiredOrRevoked(Instant.ofEpochMilli(now));

        logger.info(
            "Token cleanup completed. Blacklist removed={}, RefreshTokens removed={}",
            deletedBlacklist,
            deletedRefreshTokens
        );
    }

}
