package com.hc.Security.controller;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.hc.Security.dto.LoginRequest;
import com.hc.Security.service.UserService;

@RestController
@RequestMapping("/admin")
public class AdminController {
    
    private final UserService userService;

    public AdminController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/register")
    public String registerAdmin(@RequestBody LoginRequest request) {
        request.setLoginType((short) 1);
        return userService.register(request);
    } 

}
