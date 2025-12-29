package com.hc.Security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/user")
    public String user() {
        return "User Access";
    }

    @GetMapping("/admin")
    public String admin() {
        return "Admin Access";
    }
}
