
package com.poc.oauth.wam.controller.external;

import com.poc.oauth.wam.service.AccessTokenService;
import com.poc.oauth.wam.service.ClientAuthenticationService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/oauth")
public class OAuthTokenController {

    private final ClientAuthenticationService authenticationService;
    private final AccessTokenService accessTokenService;

    public OAuthTokenController(
            ClientAuthenticationService authenticationService,
            AccessTokenService accessTokenService) {
        this.authenticationService = authenticationService;
        this.accessTokenService = accessTokenService;
    }

    @PostMapping(
            value = "/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE
    )
    public ResponseEntity<?> generateToken(
            @RequestParam String client_id,
            @RequestParam String grant_type,
            @RequestParam String client_assertion_type,
            @RequestParam String client_assertion,
            @RequestParam(defaultValue = "openid") String scope
    ) throws Exception {

        // 1. Validar grant type
        if (!"client_credentials".equals(grant_type)) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "unsupported_grant_type"));
        }

        // 2. Validar tipo de Client Assertion
        String expectedAssertionType =
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

        if (!expectedAssertionType.equals(client_assertion_type)) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "invalid_request"));
        }

        // 3. Autenticar cliente
        boolean authenticated = authenticationService.authenticate(
                client_id,
                client_assertion
        );

        if (!authenticated) {
            return ResponseEntity.status(401)
                    .body(Map.of("error", "invalid_client"));
        }

        // 4. Generar Access Token
        String accessToken = accessTokenService.generateAccessToken(
                client_id,
                scope
        );

        // 5. Responder según OAuth 2.0
        return ResponseEntity.ok(Map.of(
                "access_token", accessToken,
                "token_type", "Bearer",
                "expires_in", 3600,
                "scope", scope
        ));
    }
}
