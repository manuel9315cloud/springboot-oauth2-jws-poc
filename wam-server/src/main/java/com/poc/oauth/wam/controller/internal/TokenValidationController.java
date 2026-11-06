
package com.poc.oauth.wam.controller.internal;

import com.poc.oauth.wam.service.AccessTokenService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/internal/tokens")
public class TokenValidationController {

    private final AccessTokenService accessTokenService;

    public TokenValidationController(
            AccessTokenService accessTokenService) {
        this.accessTokenService = accessTokenService;
    }

    @PostMapping("/validate")
    public ResponseEntity<?> validate(
            @RequestBody Map<String, String> request) {

        String token = request.get("token");

        boolean valid =
                accessTokenService.validateAccessToken(token);

        if (!valid) {
            return ResponseEntity.status(401)
                    .body(Map.of("valid", false));
        }

        return ResponseEntity.ok(Map.of("valid", true));
    }
}
