package com.hc.Security.security.jwt;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.DigestUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import com.hc.Security.repository.BlackListDAO;
import com.hc.Security.security.CustomUserDetailsService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter{
    
    private static Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
  
    private final String SECRET_SALT = "SomeSecretSaltValue";

    private final JwtTokenProvider tokenProvider;
    private final CustomUserDetailsService userDetailsService;
    private final BlackListDAO tokenBlacklistRepository;

    private static final List<String> PUBLIC_ENDPOINTS = List.of(
            "/css/",
            "/js/",
            "/images/",
            "/favicon.ico",
            "/login",
            "/auth/",
            "/.well-known/", "/auth/user/login",
            "/user/register",
            "/refresh-token/rotate",
            "/login"
        );

    public JwtAuthenticationFilter(
            JwtTokenProvider tokenProvider,
            CustomUserDetailsService userDetailsService,
            BlackListDAO tokenBlacklistRepository) {
        this.tokenProvider = tokenProvider;
        this.userDetailsService = userDetailsService;
        this.tokenBlacklistRepository = tokenBlacklistRepository;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getServletPath();

        if (HttpMethod.OPTIONS.matches(request.getMethod())) {
            return true;
        }

        return PUBLIC_ENDPOINTS.stream().anyMatch(path::startsWith);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        logger.info("JwtAuthenticationFilter invoked for request: " + request.getRequestURI());
        String token = extractTokenFromCookie(request);
        if(token == null){
            String header = request.getHeader("Authorization");
            if(header != null && header.startsWith("Bearer ")){
                token = header.substring(7);
            }
        }
        
        if (token != null) {
            if (tokenBlacklistRepository.existsById(hash(token))) {

                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                throw new BadCredentialsException("Token is blacklisted");
            }
            
            String username = tokenProvider.getUsername(token);

            UserDetails userDetails =
                    userDetailsService.loadUserByUsername(username);

            Authentication auth =
                    new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(auth);
        }

        filterChain.doFilter(request, response);
    }

    private String hash(String token) {
        return DigestUtils.md5DigestAsHex(
                (token + SECRET_SALT).getBytes(StandardCharsets.UTF_8));
    }

    private String extractTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() == null) return null;

        for (Cookie cookie : request.getCookies()) {
            if ("ACCESS_TOKEN".equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
    
}
