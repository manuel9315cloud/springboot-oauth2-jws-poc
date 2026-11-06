package apigee_simulator.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Service
public class GatewayService {

    @Value("${gateway.api-key}")
    private String apiKey;

    @Value("${gateway.api-secret}")
    private String apiSecret;

    public boolean validateCredentials(String authorization) {

        if (authorization == null ||
                !authorization.startsWith("Basic ")) {
            return false;
        }

        try {
            String encodedCredentials =
                    authorization.substring(6);

            String decodedCredentials = new String(
                    Base64.getDecoder().decode(encodedCredentials),
                    StandardCharsets.UTF_8
            );

            String expectedCredentials = apiKey + ":" + apiSecret;

            return expectedCredentials.equals(decodedCredentials);

        } catch (IllegalArgumentException exception) {
            return false;
        }
    }
}
