package com.novabank.auth.user;

import org.springframework.data.jpa.domain.Specification;
import org.springframework.util.StringUtils;

/**
 * Optional search filters built as criteria predicates. Building the query from the
 * filters that are present avoids "? IS NULL" style parameters, which Db2 rejects
 * for untyped parameter markers.
 */
public final class UserSpecs {

    private UserSpecs() {
    }

    public static Specification<User> search(Role role, UserStatus status, String q) {
        return (root, query, cb) -> {
            var predicates = new java.util.ArrayList<jakarta.persistence.criteria.Predicate>();
            if (role != null) {
                predicates.add(cb.equal(root.get("role"), role));
            }
            if (status != null) {
                predicates.add(cb.equal(root.get("status"), status));
            }
            if (StringUtils.hasText(q)) {
                String like = "%" + q.trim().toLowerCase() + "%";
                predicates.add(cb.or(
                        cb.like(cb.lower(root.<String>get("fullName")), like),
                        cb.like(cb.lower(root.<String>get("email")), like)));
            }
            return cb.and(predicates.toArray(jakarta.persistence.criteria.Predicate[]::new));
        };
    }
}
