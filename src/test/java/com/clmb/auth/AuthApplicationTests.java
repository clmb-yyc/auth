package com.clmb.auth;

import com.clmb.auth.account.User;
import com.clmb.auth.account.UserRepo;
import com.clmb.auth.tokens.RefreshRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import javax.crypto.spec.SecretKeySpec;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthApplicationTests {
    private static final String CREDENTIALS = """
            {"username":"climber","password":"password123","role":"STAFF"}
            """;

    @Autowired MockMvc mvc;
    @Autowired JsonMapper json;
    @Autowired JdbcTemplate database;
    @Autowired UserRepo users;
    @Autowired PasswordEncoder passwords;
    @Value("${auth.jwt.secret}") String signingSecret;

    @BeforeEach
    void clearUsers() {
        database.update("DELETE FROM users");
    }

    @Test
    void signupAndLoginIssueSignedTokensWithoutExposingCredentials() throws Exception {
        send("/signup", CREDENTIALS)
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.role").value("VIEWER"))
                .andExpect(jsonPath("$.passwordHash").doesNotExist());
        send("/signup", CREDENTIALS).andExpect(status().isConflict());
        send("/login", CREDENTIALS.replace("password123", "wrong")).andExpect(status().isUnauthorized());

        User user = users.findByUsername("climber");
        assertThat(user.getPasswordHash()).startsWith("{bcrypt}");
        assertThat(passwords.matches("password123", user.getPasswordHash())).isTrue();

        JsonNode tokens = login();
        Jwt jwt = decode(tokens);
        assertThat(jwt.getSubject()).isEqualTo(user.getId().toString());
        assertThat(jwt.getClaimAsString("preferred_username")).isEqualTo(user.getUsername());
        assertThat(jwt.getClaimAsStringList("authorities")).containsExactly("ROLE_VIEWER");
        assertThat(Duration.between(jwt.getIssuedAt(), jwt.getExpiresAt())).isEqualTo(Duration.ofMinutes(15));

        String storedHash = database.queryForObject("SELECT token_hash FROM refresh_tokens", String.class);
        assertThat(storedHash).matches("[0-9a-f]{64}").isNotEqualTo(tokens.get("refreshToken").asString());
    }

    @Test
    void refreshRotatesTheTokenAndReadsTheCurrentRole() throws Exception {
        send("/signup", CREDENTIALS).andExpect(status().isCreated());
        JsonNode first = login();
        String oldToken = first.get("refreshToken").asString();
        database.update("UPDATE users SET role = 'STAFF' WHERE username = 'climber'");

        JsonNode rotated = read(refresh(oldToken).andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store")));
        String newToken = rotated.get("refreshToken").asString();
        assertThat(newToken).isNotEqualTo(oldToken);
        assertThat(decode(rotated).getClaimAsStringList("authorities")).containsExactly("ROLE_STAFF");

        refresh(oldToken).andExpect(status().isUnauthorized());
        refresh(first.get("accessToken").asString()).andExpect(status().isUnauthorized());
        database.update("UPDATE refresh_tokens SET expires_at = ?", Timestamp.from(Instant.now().minusSeconds(60)));
        refresh(newToken).andExpect(status().isUnauthorized());
    }

    @Test
    void concurrentRequestsCanRedeemARefreshTokenOnlyOnce() throws Exception {
        send("/signup", CREDENTIALS).andExpect(status().isCreated());
        String token = login().get("refreshToken").asString();
        CyclicBarrier start = new CyclicBarrier(2);
        try (var executor = Executors.newFixedThreadPool(2)) {
            Callable<Integer> redeem = () -> {
                start.await(10, TimeUnit.SECONDS);
                return refresh(token).andReturn().getResponse().getStatus();
            };
            var first = executor.submit(redeem);
            var second = executor.submit(redeem);
            assertThat(List.of(first.get(15, TimeUnit.SECONDS), second.get(15, TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder(200, 401);
        }
        assertThat(database.queryForObject("SELECT COUNT(*) FROM refresh_tokens", Integer.class)).isEqualTo(1);
    }

    private JsonNode login() throws Exception {
        return read(send("/login", CREDENTIALS)
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(900))
                .andExpect(jsonPath("$.refreshExpiresIn").value(604800)));
    }

    private ResultActions refresh(String token) throws Exception {
        return send("/refresh", json.writeValueAsString(new RefreshRequest(token)));
    }

    private ResultActions send(String endpoint, String body) throws Exception {
        return mvc.perform(post("/api/auth" + endpoint).contentType(MediaType.APPLICATION_JSON).content(body));
    }

    private JsonNode read(ResultActions response) throws Exception {
        return json.readTree(response.andReturn().getResponse().getContentAsString());
    }

    private Jwt decode(JsonNode tokens) {
        byte[] key = Base64.getDecoder().decode(signingSecret);
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withSecretKey(new SecretKeySpec(key, "HmacSHA256"))
                .macAlgorithm(MacAlgorithm.HS256).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer("clmb-auth"));
        return decoder.decode(tokens.get("accessToken").asString());
    }
}
