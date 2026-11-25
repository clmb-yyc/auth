package com.clmb.auth.authentication;

import com.clmb.auth.account.User;
import com.clmb.auth.account.UserRepo;
import com.clmb.auth.refresh.RefreshService;
import com.clmb.auth.tokens.TokenResponse;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

@Service
public class AuthService {
    private final UserRepo users;
    private final RefreshService sessions;
    private final PasswordEncoder passwords;
    private final AuthenticationManager authenticationManager;

    public AuthService(UserRepo users, RefreshService sessions, PasswordEncoder passwords,
                       AuthenticationManager authenticationManager) {
        this.users = users;
        this.sessions = sessions;
        this.passwords = passwords;
        this.authenticationManager = authenticationManager;
    }

    public User signup(String username, String password) {
        if (username == null || !username.matches("[A-Za-z0-9._-]{3,64}")
                || !validPassword(password)
                || password.codePointCount(0, password.length()) < 8) {
            throw new InvalidInputException("Please check your username and password and try again.");
        }

        User user = new User();
        user.setId(UUID.randomUUID());
        user.setUsername(username);
        user.setPassword(passwords.encode(password));
        user.setRole(User.Role.VIEWER);

        try {
            return users.saveAndFlush(user);
        } catch (DataIntegrityViolationException exception) {
            if (users.findByUsername(username) != null) {
                throw new UsernameAlreadyExistsException();
            }
            throw exception;
        }
    }

    @Transactional
    public TokenResponse login(String username, String password) {
        if (username == null || username.isBlank() || !validPassword(password)) {
            throw new InvalidInputException("Please check your username and password and try again.");
        }

        Authentication authentication = authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(username, password));
        User user = users.findByUsername(authentication.getName());
        if (user == null) {
            throw new BadCredentialsException("Invalid credentials");
        }
        return sessions.startSession(user);
    }

    private boolean validPassword(String password) {
        return password != null && !password.isEmpty() && password.getBytes(StandardCharsets.UTF_8).length <= 72;
    }

    static class InvalidInputException extends RuntimeException {
        InvalidInputException(String message) {
            super(message);
        }
    }

    static class UsernameAlreadyExistsException extends RuntimeException {
        UsernameAlreadyExistsException() {
            super("We couldn't create an account with those details.");
        }
    }
}
