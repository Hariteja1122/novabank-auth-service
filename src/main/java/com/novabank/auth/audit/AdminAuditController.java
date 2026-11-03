package com.novabank.auth.audit;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

/**
 * The central NovaBank audit trail: sign-ins (including failed ones), profile and admin user
 * changes from auth-service, plus everything account-service and transaction-service report
 * through /internal/audit. ROLE_ADMIN at the gateway and here. Reading it is not audited.
 */
@RestController
@RequestMapping("/api/admin/audit")
public class AdminAuditController {

    private final AuditLogRepository repo;
    private final ObjectMapper json;

    public AdminAuditController(AuditLogRepository repo, ObjectMapper json) {
        this.repo = repo;
        this.json = json;
    }

    @GetMapping
    public Page<AuditEntryDto> search(@RequestParam(required = false) String action,
                                      @RequestParam(required = false) String service,
                                      @RequestParam(required = false) AuditLog.Outcome outcome,
                                      @RequestParam(required = false) String actor,
                                      @RequestParam(required = false) String targetId,
                                      @RequestParam(required = false) String q,
                                      @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant from,
                                      @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant to,
                                      @RequestParam(defaultValue = "0") int page,
                                      @RequestParam(defaultValue = "20") int size) {
        var pageable = PageRequest.of(page, Math.min(size, 100),
                Sort.by(Sort.Direction.DESC, "createdAt").and(Sort.by(Sort.Direction.DESC, "id")));
        return repo.findAll(AuditSpecs.filter(action, service, outcome, actor, targetId, q, from, to), pageable)
                .map(e -> AuditEntryDto.from(e, json));
    }
}
