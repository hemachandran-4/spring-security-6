package com.hc.Security.dto;

public class LoginRequest {

    private String username;

    private String password;
    
    private Short loginType;

    public LoginRequest() {
    }

    public LoginRequest(String username, String password, Short loginType) {
        this.username = username;
        this.password = password;
        this.loginType = loginType;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Short getLoginType() {
        return loginType;
    }

    public void setLoginType(Short loginType) {
        this.loginType = loginType;
    }
    
}
