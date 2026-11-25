package com.clmb.auth.tokens;

public record AccessToken(String accessToken, String tokenType, long expiresIn,
                          String refreshToken, long refreshExpiresIn) {}
