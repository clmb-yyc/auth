package com.clmb.auth.refresh;

import com.clmb.auth.account.User;
import com.clmb.auth.account.UserRepo;
import com.clmb.auth.tokens.AccessTokenIssuer;
import com.clmb.auth.tokens.TokenResponse;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

@Service
public class RefreshService {
    private static final Duration REFRESH_TOKEN_TTL = Duration.ofDays(7);

    private final UserRepo users;
    private final RefreshTokenRepo refreshTokens;
    private final AccessTokenIssuer accessTokens;
    private final SecureRandom random = new SecureRandom();

    public RefreshService(UserRepo users, RefreshTokenRepo refreshTokens, AccessTokenIssuer accessTokens) {
        this.users = users;
        this.refreshTokens = refreshTokens;
        this.accessTokens = accessTokens;
    }

    @Transactional
    public TokenResponse startSession(User user) {
        return issueTokens(user);
    }

    @Transactional
    public TokenResponse refresh(String token) {
        if (token == null || !token.matches("[A-Za-z0-9_-]{43}")) {
            throw new InvalidRefreshTokenException();
        }

        RefreshToken stored = refreshTokens.findByTokenHash(hashToken(token))
                .orElseThrow(InvalidRefreshTokenException::new);
        if (!stored.getExpiresAt().isAfter(Instant.now())) {
            throw new InvalidRefreshTokenException();
        }
        User user = users.findById(stored.getUserId()).orElseThrow(InvalidRefreshTokenException::new);

        // The lock, deletion, and new token are part of one transaction.
        refreshTokens.delete(stored);
        return issueTokens(user);
    }

    private TokenResponse issueTokens(User user) {
        Instant now = Instant.now();
        Jwt accessToken = accessTokens.issue(user, now);
        byte[] randomBytes = new byte[32];
        random.nextBytes(randomBytes);
        String refreshToken = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        refreshTokens.save(new RefreshToken(hashToken(refreshToken), user.getId(), now.plus(REFRESH_TOKEN_TTL)));
        long expiresIn = Duration.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()).toSeconds();
        return new TokenResponse(accessToken.getTokenValue(), "Bearer", expiresIn, refreshToken,
                REFRESH_TOKEN_TTL.toSeconds());
    }

    private String hashToken(String token) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    static class InvalidRefreshTokenException extends RuntimeException {}
}
