package com.novabank.auth.audit;

import jakarta.persistence.criteria.Predicate;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/** Optional audit filters as criteria predicates (Db2 rejects untyped "? IS NULL"). */
public final class AuditSpecs {

    private AuditSpecs() {
    }

    /**
     * @param actor a user id (exact match on ACTOR_ID) or part of an email address
     * @param q     free text matched against the target id and correlation id
     */
    public static Specification<AuditLog> filter(String action, String service, AuditLog.Outcome outcome,
                                                 String actor, String targetId, String q, Instant from, Instant to) {
        return (root, query, cb) -> {
            List<Predicate> p = new ArrayList<>();
            if (StringUtils.hasText(action)) {
                p.add(cb.equal(root.get("action"), action.trim().toUpperCase()));
            }
            if (StringUtils.hasText(service)) {
                p.add(cb.equal(root.get("service"), service.trim().toLowerCase()));
            }
            if (outcome != null) {
                p.add(cb.equal(root.get("outcome"), outcome));
            }
            if (StringUtils.hasText(actor)) {
                String a = actor.trim();
                if (a.chars().allMatch(Character::isDigit) && a.length() < 19) {
                    p.add(cb.equal(root.get("actorId"), Long.valueOf(a)));
                } else {
                    p.add(cb.like(cb.lower(root.<String>get("actorEmail")), "%" + a.toLowerCase() + "%"));
                }
            }
            if (StringUtils.hasText(targetId)) {
                p.add(cb.equal(root.get("targetId"), targetId.trim()));
            }
            if (StringUtils.hasText(q)) {
                String like = "%" + q.trim().toLowerCase() + "%";
                p.add(cb.or(
                        cb.like(cb.lower(root.<String>get("targetId")), like),
                        cb.like(cb.lower(root.<String>get("correlationId")), like)));
            }
            if (from != null) {
                p.add(cb.greaterThanOrEqualTo(root.get("createdAt"), from));
            }
            if (to != null) {
                p.add(cb.lessThan(root.get("createdAt"), to));
            }
            return cb.and(p.toArray(Predicate[]::new));
        };
    }
}
