package com.poc.payments.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.Map;

@Service
public class TokenValidationService {

    private final RestClient restClient;

    public TokenValidationService(
            @Value("${integration.wam.url}") String wamUrl) {

        this.restClient = RestClient.builder()
                .baseUrl(wamUrl)
                .build();
    }

    public boolean validate(String token) {

        Map response = restClient.post()
                .uri("/internal/tokens/validate")
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("token", token))
                .retrieve()
                .body(Map.class);

        return response != null
                && Boolean.TRUE.equals(response.get("valid"));
    }
}
