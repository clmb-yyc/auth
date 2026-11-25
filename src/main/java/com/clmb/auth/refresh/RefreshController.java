package com.clmb.auth.refresh;

import com.clmb.auth.tokens.TokenResponse;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class RefreshController {
    private final RefreshService sessions;

    public RefreshController(RefreshService sessions) {
        this.sessions = sessions;
    }

    @PostMapping("/api/auth/refresh")
    public ResponseEntity<TokenResponse> refresh(@RequestBody RefreshRequest request) {
        TokenResponse tokens = sessions.refresh(request.refreshToken());
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(tokens);
    }

    @ExceptionHandler(RefreshService.InvalidRefreshTokenException.class)
    ResponseEntity<Map<String, String>> invalidRefreshToken() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("message", "Your session has expired. Please sign in again."));
    }
}
