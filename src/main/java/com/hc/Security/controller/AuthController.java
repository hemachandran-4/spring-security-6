package com.hc.Security.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
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


    @PostMapping("/user/register")
    public String register(@RequestBody LoginRequest request) {
        request.setLoginType((short) 0);
        return authService.register(request);
    }

    @PostMapping("/admin/register")
    public String registerAdmin(@RequestBody LoginRequest request) {
        request.setLoginType((short) 1);
        return authService.register(request);
    } 
}