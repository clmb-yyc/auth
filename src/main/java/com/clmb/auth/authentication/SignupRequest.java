package com.clmb.auth.authentication;

public record SignupRequest(String username, String password, String firstName, String lastName, String email) {}
