
package apigee_simulator.controller;

import apigee_simulator.service.GatewayService;
import apigee_simulator.service.WamTokenService;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/oauth")
public class TokenController {

    private final GatewayService gatewayService;
    private final WamTokenService wamTokenService;

    public TokenController(
            GatewayService gatewayService,
            WamTokenService wamTokenService) {
        this.gatewayService = gatewayService;
        this.wamTokenService = wamTokenService;
    }

    @PostMapping(
            value = "/token",
            consumes = "application/x-www-form-urlencoded"
    )
    public ResponseEntity<?> token(
            @RequestHeader(value = "Authorization", required = false)
            String authorization,

            @RequestParam MultiValueMap<String, String> parameters) {

        // 1. Validar credenciales del Gateway
        if (!gatewayService.validateCredentials(authorization)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid API Key or API Secret");
        }

        // 2. Reenviar solicitud OAuth a WAM
        return wamTokenService.requestToken(parameters);
    }
}
