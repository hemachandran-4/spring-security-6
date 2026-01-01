package com.hc.Security.security.jwt;

import java.util.Date;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtTokenProvider {

    private final long expiryMillis;

    private final SecretKey signingKey;

    public JwtTokenProvider(
        /* 
            * 1. Local Deployment - application.properties
            * 2. Production Deployment - Environment Variables
            * 3. AWS - AWS Secrets Manager
            * 4. GCP - Secret Manager
            * 5. Azure - Azure Key Vault
            * 6. Kubernetes - Kubernetes Secrets
            * 7. Docker - .env File
            * 8. HashiCorp Vault
        */
            @Value("${jwt.secret}") String base64Secret, 
            @Value("${jwt.expiry}") long expiryMillis) {

        this.signingKey = Keys.hmacShaKeyFor(
                Decoders.BASE64.decode(base64Secret)
        );
        this.expiryMillis = expiryMillis;
    }

    public String generateToken(Authentication auth) {
        return Jwts.builder()
                .setSubject(auth.getName())
                .claim("roles", auth.getAuthorities())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiryMillis))
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public String getUsername(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public long getExpiration(String token) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        return claims.getExpiration().getTime();
    }
    
    
}
