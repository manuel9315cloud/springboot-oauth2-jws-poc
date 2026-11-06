package com.poc.oauth.wam.service;

import com.poc.oauth.wam.security.JwtAssertionVerifier;
import org.springframework.stereotype.Service;

@Service
public class ClientAuthenticationService {

    private final JwtAssertionVerifier assertionVerifier;

    public ClientAuthenticationService(
            JwtAssertionVerifier assertionVerifier) {
        this.assertionVerifier = assertionVerifier;
    }

    public boolean authenticate(
            String clientId,
            String clientAssertion
    ) throws Exception {

        System.out.println("========== CLIENT AUTHENTICATION ==========");
        System.out.println("CLIENT ID: " + clientId);

        // 1. Validar que el cliente exista
        if (!"nubiz-client".equals(clientId)) {
            System.out.println("ERROR: CLIENT ID INVALID");
            return false;
        }

        System.out.println("CLIENT ID VALID");

        // 2. Verificar firma, claims y JTI del JWT
        boolean valid = assertionVerifier.verifyAssertion(clientAssertion);

        System.out.println("ASSERTION VALID: " + valid);
        System.out.println("===========================================");

        return valid;
    }
}