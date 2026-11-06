
package com.poc.payments.controller;

import com.poc.payments.crypto.JwsSigningService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/test/jws")
public class JwsTestController {

    private final JwsSigningService signingService;

    public JwsTestController(JwsSigningService signingService) {
        this.signingService = signingService;
    }

    @PostMapping("/sign")
    public Map<String, String> sign() throws Exception {

        String payload = """
                {
                    "paymentId": "PAY-10001",
                    "status": "APPROVED",
                    "amount": 250000,
                    "currency": "COP"
                }
                """;

        String signedPayload = signingService.sign(payload);

        return Map.of("signed_payload", signedPayload);
    }
}
