package com.hc.Security.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.hc.Security.dto.LoginResponse;
import com.hc.Security.service.RefreshTokenService;

@RestController
@RequestMapping("/refresh-token")
public class RefreshTokenController {

    private final RefreshTokenService refreshTokenService;

    public RefreshTokenController(RefreshTokenService refreshTokenService) {
        this.refreshTokenService = refreshTokenService;
    }
    
    @PostMapping("/rotate")
    public LoginResponse refresh(@RequestHeader(HttpHeaders.AUTHORIZATION) String header) {
        String refreshTokenValue = header.substring(7);
        return refreshTokenService.refreshToken(refreshTokenValue);
    }

}
