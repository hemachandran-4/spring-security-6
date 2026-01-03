package com.hc.Security.dto;

public record RefreshTokenDTO(
    String refreshToken,
    Long userId
) {}
