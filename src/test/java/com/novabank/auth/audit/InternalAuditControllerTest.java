package com.novabank.auth.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.novabank.auth.common.GlobalExceptionHandler;
import com.novabank.auth.config.InternalApiKeyFilter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class InternalAuditControllerTest {

    private final AuditWriter writer = mock(AuditWriter.class);
    private final ObjectMapper json = new ObjectMapper().registerModule(new JavaTimeModule());
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.standaloneSetup(new InternalAuditController(writer, json))
                .setControllerAdvice(new GlobalExceptionHandler())
                .setMessageConverters(new MappingJackson2HttpMessageConverter(json))
                .build();
    }

    private AuditLog send(String body, int expected) throws Exception {
        mvc.perform(post("/internal/audit").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().is(expected));
        if (expected != 202) {
            verify(writer, never()).write(any());
            return null;
        }
        ArgumentCaptor<AuditLog> row = ArgumentCaptor.forClass(AuditLog.class);
        verify(writer).write(row.capture());
        return row.getValue();
    }

    @Test
    void storesAnEventFromAccountService() throws Exception {
        Instant at = Instant.now().minusSeconds(3);
        AuditLog row = send("""
                {"service":"accounts","createdAt":"%s","actorId":1,"actorRole":"ADMIN","actorEmail":"admin@novabank.dev",
                 "action":"ACCOUNT_STATUS_CHANGE","targetType":"ACCOUNT","targetId":"100245180031",
                 "outcome":"SUCCESS","httpStatus":200,"details":{"from":"ACTIVE","to":"FROZEN"},
                 "correlationId":"c-123","sourceIp":"203.0.113.7"}
                """.formatted(at), 202);

        assertThat(row.getService()).isEqualTo("accounts");
        assertThat(row.getCreatedAt()).isEqualTo(at);
        assertThat(row.getActorId()).isEqualTo(1L);
        assertThat(row.getAction()).isEqualTo("ACCOUNT_STATUS_CHANGE");
        assertThat(row.getTargetId()).isEqualTo("100245180031");
        assertThat(row.getDetails()).isEqualTo("{\"from\":\"ACTIVE\",\"to\":\"FROZEN\"}");
        assertThat(row.getCorrelationId()).isEqualTo("c-123");
    }

    @Test
    void aTimestampFromTheFutureIsReplacedWithNow() throws Exception {
        Instant future = Instant.now().plus(Duration.ofHours(2));
        AuditLog row = send("""
                {"service":"transactions","createdAt":"%s","action":"DEPOSIT","outcome":"FAILURE","reason":"Account is FROZEN"}
                """.formatted(future), 202);

        assertThat(row.getCreatedAt()).isBefore(future.minus(Duration.ofHours(1)));
        assertThat(row.getReason()).isEqualTo("Account is FROZEN");
    }

    @Test
    void anotherServiceCannotWriteAsAuth() throws Exception {
        send("""
                {"service":"auth","action":"LOGIN","outcome":"SUCCESS"}
                """, 400);
    }

    @Test
    void malformedActionIsRejected() throws Exception {
        send("""
                {"service":"accounts","action":"drop table","outcome":"SUCCESS"}
                """, 400);
    }

    @Test
    void internalEndpointsNeedTheInternalKey() throws Exception {
        InternalApiKeyFilter filter = new InternalApiKeyFilter("right-key");

        MockHttpServletResponse missing = new MockHttpServletResponse();
        filter.doFilter(new MockHttpServletRequest("POST", "/internal/audit"), missing, new MockFilterChain());
        assertThat(missing.getStatus()).isEqualTo(401);

        MockHttpServletRequest wrong = new MockHttpServletRequest("POST", "/internal/audit");
        wrong.addHeader(InternalApiKeyFilter.HEADER, "wrong-key");
        MockHttpServletResponse wrongResponse = new MockHttpServletResponse();
        filter.doFilter(wrong, wrongResponse, new MockFilterChain());
        assertThat(wrongResponse.getStatus()).isEqualTo(401);

        MockHttpServletRequest right = new MockHttpServletRequest("POST", "/internal/audit");
        right.addHeader(InternalApiKeyFilter.HEADER, "right-key");
        MockHttpServletResponse ok = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        filter.doFilter(right, ok, chain);
        assertThat(chain.getRequest()).isNotNull();
    }
}
