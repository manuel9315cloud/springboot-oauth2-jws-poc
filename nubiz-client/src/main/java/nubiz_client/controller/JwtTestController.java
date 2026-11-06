package nubiz_client.controller;

import nubiz_client.security.JwtAssertionService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/test")
public class JwtTestController {

    private final JwtAssertionService assertionService;

    public JwtTestController(JwtAssertionService assertionService) {
        this.assertionService = assertionService;
    }

    @GetMapping("/assertion")
    public String generate() throws Exception {
        return assertionService.generateAssertion();
    }
}