package com.novabank.auth.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.util.Map;

/** Calls account-service's internal API, authenticated with the shared internal key. */
@Component
public class AccountClient {

    private static final Logger log = LoggerFactory.getLogger(AccountClient.class);

    private final RestClient client;

    public AccountClient(RestClient.Builder builder,
                         @Value("${novabank.services.account-url}") String accountUrl,
                         @Value("${novabank.security.internal-api-key}") String internalKey) {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(3000);
        factory.setReadTimeout(5000);
        this.client = builder
                .baseUrl(accountUrl)
                .requestFactory(factory)
                .defaultHeader("X-Internal-Api-Key", internalKey)
                .build();
    }

    public void openDefaultAccount(Long customerId, String customerName) {
        try {
            client.post()
                    .uri("/internal/accounts")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("customerId", customerId, "customerName", customerName, "accountType", "CHECKING"))
                    .retrieve()
                    .toBodilessEntity();
            log.info("Opened default checking account for customer {}", customerId);
        } catch (RestClientException ex) {
            log.warn("Could not open default account for customer {}: {}", customerId, ex.getMessage());
        }
    }
}
