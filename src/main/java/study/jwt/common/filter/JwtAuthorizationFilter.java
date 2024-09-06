package study.jwt.common.filter;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import study.jwt.common.exception.customexception.userexception.UserNotFoundException;
import study.jwt.common.security.auth.AuthUserService;
import study.jwt.common.security.exception.CustomSecurityException;
import study.jwt.common.security.exception.errorcode.SecurityErrorCode;
import study.jwt.common.security.jwt.JwtProvider;
import study.jwt.domain.user.entity.User;
import study.jwt.domain.user.repository.UserRepository;

import java.io.IOException;

import static study.jwt.common.exception.errorcode.UserErrorCode.NOT_SIGNED_UP_USER;

@Slf4j
public class JwtAuthorizationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;
    private final UserRepository userRepository;
    private final AuthUserService authUserService;

    public JwtAuthorizationFilter(JwtProvider jwtProvider, UserRepository userRepository, AuthUserService authUserService) {
        this.jwtProvider = jwtProvider;
        this.userRepository = userRepository;
        this.authUserService = authUserService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain
    ) throws ServletException, IOException {
        String accessTokenValue = jwtProvider.getAccessTokenFromHeader(request);

        if (StringUtils.hasText(accessTokenValue) && jwtProvider.validateToken(request, accessTokenValue)) {

            String username = jwtProvider.getUserInfoFromToken(accessTokenValue).getSubject();
            User findUser = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UserNotFoundException(NOT_SIGNED_UP_USER));
            if (findUser.getRefreshToken() != null) {
                if (isValidateUsername(username, findUser)) {

                    log.info("Token 인증 완료");
                    Claims info = jwtProvider.getUserInfoFromToken(accessTokenValue);
                    setAuthentication(info.getSubject());
                }
            } else {
                log.error("유효하지 않은 Refersh Token");
                request.setAttribute("exception", new CustomSecurityException(SecurityErrorCode.INVALID_JWT_SIGNATURE));
            }
        }

        filterChain.doFilter(request, response);

        }

    private boolean isValidateUsername(String username, User findUser) {
        return username.equals(findUser.getUsername());
    }

    private void setAuthentication(String username) {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        Authentication authentication = createAuthentication(username);
        context.setAuthentication(authentication);

        SecurityContextHolder.setContext(context);
    }

    private Authentication createAuthentication(String username) {
        UserDetails userDetails = authUserService.loadUserByUsername(username);
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    }


}
