package com.novabank.auth.auth;

import com.novabank.auth.audit.Audit;
import com.novabank.auth.auth.AuthDtos.LoginRequest;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdviceAdapter;

import java.lang.reflect.Type;

/**
 * Records the email of every sign-in attempt on its audit row, including attempts that fail
 * validation before AuthService runs. Runs after the body is parsed and before validation.
 * It reads the email field only. The password is never touched here.
 */
@ControllerAdvice
public class LoginAttemptAuditAdvice extends RequestBodyAdviceAdapter {

    @Override
    public boolean supports(MethodParameter parameter, Type targetType,
                            Class<? extends HttpMessageConverter<?>> converterType) {
        return LoginRequest.class.equals(targetType);
    }

    @Override
    public Object afterBodyRead(Object body, HttpInputMessage inputMessage, MethodParameter parameter,
                                Type targetType, Class<? extends HttpMessageConverter<?>> converterType) {
        if (body instanceof LoginRequest req && req.email() != null) {
            Audit.attemptedEmail(req.email().trim());
        }
        return body;
    }
}
