
package apigee_simulator.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

@Service
public class WamTokenService {

    private final RestClient restClient;

    public WamTokenService(
            @Value("${integration.wam.url}") String wamUrl) {

        this.restClient = RestClient.builder()
                .baseUrl(wamUrl)
                .build();
    }

    public ResponseEntity<String> requestToken(
            MultiValueMap<String, String> parameters) {

        return restClient.post()
                .uri("/oauth/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(parameters)
                .exchange((request, response) -> {

                    String responseBody =
                            new String(response.getBody().readAllBytes());

                    return ResponseEntity
                            .status(response.getStatusCode())
                            .contentType(
                                    response.getHeaders()
                                            .getContentType() != null
                                            ? response.getHeaders().getContentType()
                                            : MediaType.APPLICATION_JSON
                            )
                            .body(responseBody);
                });
    }
}
