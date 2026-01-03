package com.hc.Security.service;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;

import com.hc.Security.entity.TokenBlacklist;
import com.hc.Security.repository.BlackListDAO;

@Service
public class BlackListService {

    private final String secretSalt = "SomeSecretSaltValue";

    private static Logger logger = LoggerFactory.getLogger(BlackListService.class);

    private final Map<String, Long> blacklist = new ConcurrentHashMap<>();

    private final BlackListDAO blackListDAO;

    public BlackListService(BlackListDAO blackListDAO) {
        this.blackListDAO = blackListDAO;
    }

    public void blacklist(String token, long expiryTime) {
        logger.info("Blacklisting token with hash: {}", hash(token));
        blacklist.put(hash(token), expiryTime);
        TokenBlacklist tokenBlacklist = new TokenBlacklist(hash(token), expiryTime);
        blackListDAO.save(tokenBlacklist);
        logger.info("Token blacklisted until: {}", expiryTime);
    }

    public boolean isBlacklisted(String token) {
        Long expiry = blacklist.get(hash(token));
        if (expiry == null) {
            return false;
        }

        if (System.currentTimeMillis() > expiry) {
            blacklist.remove(hash(token));
            blackListDAO.deleteByTokenHash(hash(token));
            return false;
        }

        return true;
    }

    private String hash(String token) {
        return DigestUtils.md5DigestAsHex(
                (token + secretSalt).getBytes(StandardCharsets.UTF_8));
    }

     
}
