package com.hc.Security.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.hc.Security.dto.LoginRequest;
import com.hc.Security.dto.LoginResponse;
import com.hc.Security.service.AuthService;


@RestController
@RequestMapping("/auth")
public class AuthController {
    
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/user/login")
    public LoginResponse userLogin(@RequestBody LoginRequest request) {
        return authService.login(
                request.getUsername(),
                request.getPassword());
    }

    @PostMapping("/admin/login")
    public LoginResponse adminLogin(@RequestBody LoginRequest request) {
        return authService.login(
                request.getUsername(),
                request.getPassword());
    }

    @GetMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader,
        @CookieValue(name = "refresh_token", required = false) String refreshToken
    ) {
        String response = authService.logout(authorizationHeader, refreshToken);
        return new ResponseEntity<String>(response,  null, 200);
    }
    
}