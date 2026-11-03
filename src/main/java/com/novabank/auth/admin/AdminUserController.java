package com.novabank.auth.admin;

import com.novabank.auth.audit.Audit;
import com.novabank.auth.audit.Audited;
import com.novabank.auth.common.ApiException;
import com.novabank.auth.common.CurrentUser;
import com.novabank.auth.user.Role;
import com.novabank.auth.user.User;
import com.novabank.auth.user.UserDto;
import com.novabank.auth.user.UserRepository;
import com.novabank.auth.user.UserSpecs;
import com.novabank.auth.user.UserStatus;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

/** Customer administration. The gateway and this service both require ROLE_ADMIN. */
@RestController
@RequestMapping("/api/admin/users")
public class AdminUserController {

    private static final Logger log = LoggerFactory.getLogger(AdminUserController.class);

    private final UserRepository users;

    public AdminUserController(UserRepository users) {
        this.users = users;
    }

    public record StatusRequest(@NotNull UserStatus status) {
    }

    public record UserSummary(long totalCustomers, long activeCustomers, long lockedCustomers,
                              long newCustomersLast30Days, long admins) {
    }

    @GetMapping
    public Page<UserDto> search(@RequestParam(required = false) Role role,
                                @RequestParam(required = false) UserStatus status,
                                @RequestParam(required = false) String q,
                                @RequestParam(defaultValue = "0") int page,
                                @RequestParam(defaultValue = "20") int size) {
        var pageable = PageRequest.of(page, Math.min(size, 100), Sort.by(Sort.Direction.DESC, "createdAt"));
        return users.findAll(UserSpecs.search(role, status, q), pageable).map(UserDto::from);
    }

    @GetMapping("/summary")
    public UserSummary summary() {
        return new UserSummary(
                users.countByRole(Role.CUSTOMER),
                users.countByRoleAndStatus(Role.CUSTOMER, UserStatus.ACTIVE),
                users.countByRoleAndStatus(Role.CUSTOMER, UserStatus.LOCKED),
                users.countByRoleAndCreatedAtAfter(Role.CUSTOMER, Instant.now().minus(java.time.Duration.ofDays(30))),
                users.countByRole(Role.ADMIN));
    }

    @GetMapping("/{id}")
    public UserDto get(@PathVariable Long id) {
        return UserDto.from(find(id));
    }

    @PatchMapping("/{id}/status")
    @Audited(action = "USER_STATUS_CHANGE", targetType = "USER", targetParam = "id")
    @Transactional
    public UserDto updateStatus(@PathVariable Long id, @Valid @RequestBody StatusRequest req,
                                @AuthenticationPrincipal Jwt jwt) {
        User user = find(id);
        if (user.getId().equals(CurrentUser.id(jwt))) {
            throw ApiException.badRequest("You cannot change the status of your own profile");
        }
        if (user.getRole() == Role.ADMIN) {
            throw ApiException.badRequest("Admin profiles cannot be locked from the console");
        }
        Audit.detail("from", user.getStatus());
        Audit.detail("to", req.status());
        user.setStatus(req.status());
        log.info("Admin {} set user {} to {}", CurrentUser.id(jwt), id, req.status());
        return UserDto.from(user);
    }

    private User find(Long id) {
        return users.findById(id).orElseThrow(() -> ApiException.notFound("User not found"));
    }
}
