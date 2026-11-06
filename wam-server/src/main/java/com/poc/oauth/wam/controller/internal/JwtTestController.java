package com.poc.oauth.wam.controller.internal;

import com.poc.oauth.wam.security.JwtAssertionVerifier;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/test")
public class JwtTestController {

    private final JwtAssertionVerifier verifier;

    public JwtTestController(JwtAssertionVerifier verifier) {
        this.verifier = verifier;
    }

    @PostMapping("/verify")
    public boolean verify(@RequestBody String token) throws Exception {
        return verifier.verifyAssertion(token);
    }
}
