package com.hc.Security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import com.hc.Security.dto.LoginResponse;

import jakarta.servlet.http.HttpSession;

@Controller
public class ViewController {

    @GetMapping("/login")
    public String loginPage() {
        return "auth/login";
    }

    @GetMapping("/home")
    public String home(Model model, HttpSession session) {

        LoginResponse response = (LoginResponse) session.getAttribute("loginResponse");

        model.addAttribute("login", response);

        return "home";
    }



}
