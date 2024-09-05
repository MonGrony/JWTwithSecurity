package study.jwt.common.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import study.jwt.common.exception.errorResponse.ErrorResponse;
import study.jwt.common.exception.errorcode.ErrorCode;
import study.jwt.common.security.exception.CustomSecurityException;
import study.jwt.common.security.exception.errorcode.SecurityErrorCode;

import java.io.IOException;

@Slf4j(topic = "인증 예외 필터")
@Component
@RequiredArgsConstructor
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException {
        log.error("Jwt 인증 도중 예외 발생");
        Exception exception = (Exception) request.getAttribute("exception");

        if (exception instanceof CustomSecurityException e) {
            sendErrorResponse(response, e.getErrorCode());
            return;
        }

        sendErrorResponse(response, SecurityErrorCode.INVALID_JWT_SIGNATURE);
    }

    private void sendErrorResponse(HttpServletResponse response, ErrorCode errorCode) throws IOException {
        ErrorResponse errorResponse = ErrorResponse.of(errorCode);
        String body = objectMapper.writeValueAsString(errorResponse);

        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(errorCode.getHttpStatus().value());
        response.getWriter().write(body);
    }
}
