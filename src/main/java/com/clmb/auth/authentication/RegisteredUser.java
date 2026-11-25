package com.clmb.auth.authentication;

import com.clmb.auth.account.User;

import java.util.UUID;

public record RegisteredUser(UUID id, String username, User.Role role) {}
