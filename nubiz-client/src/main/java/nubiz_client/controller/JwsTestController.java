
package nubiz_client.controller;

import nubiz_client.crypto.JwsVerificationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/test/jws")
public class JwsTestController {

    private final JwsVerificationService verificationService;

    public JwsTestController(
            JwsVerificationService verificationService) {
        this.verificationService = verificationService;
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verify(
            @RequestBody Map<String, String> request) {

        try {
            String payload = verificationService.verifyAndExtractPayload(
                    request.get("signed_payload")
            );

            return ResponseEntity.ok(Map.of(
                    "valid", true,
                    "payload", payload
            ));

        } catch (Exception exception) {
            return ResponseEntity.badRequest().body(Map.of(
                    "valid", false,
                    "error", "Invalid signature or payload"
            ));
        }
    }
}
