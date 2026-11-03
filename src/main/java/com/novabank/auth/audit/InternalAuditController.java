package com.novabank.auth.audit;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Receives audit events from account-service and transaction-service, which keep no audit
 * table of their own. Protected by the internal API key (SecurityConfig.internalChain) and
 * never routed by the gateway. Callers send fire-and-forget: a failure here never fails the
 * business action that produced the event.
 */
@RestController
@RequestMapping("/internal/audit")
public class InternalAuditController {

    /** Clock skew tolerated on the caller's timestamp before we use our own. */
    private static final Duration MAX_SKEW = Duration.ofMinutes(5);

    private final AuditWriter writer;
    private final ObjectMapper json;

    public InternalAuditController(AuditWriter writer, ObjectMapper json) {
        this.writer = writer;
        this.json = json;
    }

    public record AuditEventRequest(
            @NotBlank @Pattern(regexp = "accounts|transactions") String service,
            Instant createdAt,
            Long actorId,
            @Size(max = 10) String actorRole,
            @Size(max = 120) String actorEmail,
            @NotBlank @Pattern(regexp = "[A-Z_]{1,40}") String action,
            @Size(max = 20) String targetType,
            @Size(max = 64) String targetId,
            @NotNull AuditLog.Outcome outcome,
            Integer httpStatus,
            @Size(max = 200) String reason,
            @Size(max = Audit.MAX_DETAILS) Map<String, String> details,
            @Size(max = 64) String correlationId,
            @Size(max = 200) String sourceIp) {
    }

    @PostMapping
    @ResponseStatus(HttpStatus.ACCEPTED)
    public void record(@Valid @RequestBody AuditEventRequest req) {
        AuditLog entry = new AuditLog();
        Instant now = Instant.now();
        boolean plausible = req.createdAt() != null && req.createdAt().isBefore(now.plus(MAX_SKEW));
        entry.setCreatedAt(plausible ? req.createdAt() : now);
        entry.setService(req.service());
        entry.setActorId(req.actorId());
        entry.setActorRole(req.actorRole());
        entry.setActorEmail(req.actorEmail());
        entry.setAction(req.action());
        entry.setTargetType(req.targetType());
        entry.setTargetId(req.targetId());
        entry.setOutcome(req.outcome());
        entry.setHttpStatus(req.httpStatus());
        entry.setReason(req.reason());
        entry.setDetails(toJson(req.details()));
        entry.setCorrelationId(req.correlationId());
        entry.setSourceIp(req.sourceIp());
        writer.write(entry);
    }

    private String toJson(Map<String, String> details) {
        if (details == null || details.isEmpty()) {
            return null;
        }
        Map<String, String> safe = new LinkedHashMap<>();
        details.forEach((k, v) -> safe.put(Audit.truncate(k, 40), Audit.truncate(v, Audit.MAX_VALUE_LENGTH)));
        try {
            return json.writeValueAsString(safe);
        } catch (JsonProcessingException e) {
            return null;
        }
    }
}
