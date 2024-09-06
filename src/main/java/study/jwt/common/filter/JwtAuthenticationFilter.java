package study.jwt.common.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import study.jwt.common.exception.customexception.userexception.UserNotFoundException;
import study.jwt.common.response.RestApiResponse;
import study.jwt.common.security.jwt.JwtProvider;
import study.jwt.domain.user.entity.User;
import study.jwt.domain.user.repository.UserRepository;

import java.io.IOException;

import static study.jwt.common.exception.errorcode.UserErrorCode.NOT_SIGNED_UP_USER;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final JwtProvider jwtProvider;
    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;



    public JwtAuthenticationFilter(JwtProvider jwtProvider, UserRepository userRepository, ObjectMapper objectMapper) {
        this.jwtProvider = jwtProvider;
        this.userRepository = userRepository;
        this.objectMapper = objectMapper;
        setFilterProcessesUrl("/login");
    }

//    @Override
//    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response
//    ) throws AuthenticationException {
//        try {
//            LoginRequestDto requestDto = new ObjectMapper().readValue(
//                    request.getInputStream(), LoginRequestDto.class);
//
//    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult
    ) throws IOException {
        String username = authResult.getName();
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException(NOT_SIGNED_UP_USER));

        String refreshTokenValue = jwtProvider.createAccessTokenAndRefreshToken(authResult,response);
        ((UsernamePasswordAuthenticationToken) authResult).eraseCredentials();

        user.updateRefreshToken(refreshTokenValue);
        userRepository.save(user);

        loginSuccessResponse(response);

    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException failed
    ) throws IOException, ServletException {
        super.unsuccessfulAuthentication(request, response, failed);
    }

    private void loginSuccessResponse(HttpServletResponse response) throws IOException {
        RestApiResponse apiResponse = RestApiResponse.of("로그인 성공");
        String body = objectMapper.writeValueAsString(apiResponse);

        response.setStatus(HttpStatus.OK.value());
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(body);
    }
}
