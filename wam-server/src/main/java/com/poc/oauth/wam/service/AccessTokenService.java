
package com.poc.oauth.wam.service;

import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class AccessTokenService {

    private static final long TOKEN_TTL_SECONDS = 3600;

    private final SecureRandom secureRandom = new SecureRandom();

    private final Map<String, TokenInfo> issuedTokens =
            new ConcurrentHashMap<>();

    public String generateAccessToken(String clientId, String scope) {

        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);

        String token = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(randomBytes);

        Instant expiresAt = Instant.now()
                .plusSeconds(TOKEN_TTL_SECONDS);

        issuedTokens.put(
                token,
                new TokenInfo(clientId, scope, expiresAt)
        );

        return token;
    }

    public boolean validateAccessToken(String token) {

        if (token == null || token.isBlank()) {
            return false;
        }

        TokenInfo tokenInfo = issuedTokens.get(token);

        if (tokenInfo == null) {
            return false;
        }

        if (Instant.now().isAfter(tokenInfo.expiresAt())) {
            issuedTokens.remove(token);
            return false;
        }

        return true;
    }

    public record TokenInfo(
            String clientId,
            String scope,
            Instant expiresAt
    ) {
    }
}
