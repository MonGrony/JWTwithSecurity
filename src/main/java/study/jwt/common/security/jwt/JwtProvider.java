package study.jwt.common.security.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.token.TokenService;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtProvider {

    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String REFRESH_AUTHORIZATION_HEADER = "Refresh Authorization";
    public static final String AUTHORIZATION_KEY = "auth";
    public static final String BEARER_PREFIX = "Bearer ";

    private final String ISSUER = "Mon-Groy";
    private final long ACCESS_TOKEN_TIME = 30 * 60 * 1000L; // 30분
    private final long REFRESH_TOKEN_TIME = 3 * 60 * 60 * 1000L; // 3시간


    @Value("${jwt.secret.key}")
    private String secretKey;
    private Key key;
    private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

    @PostConstruct
    public void init() {
        byte[] bytes = Base64.getDecoder().decode(secretKey);
        key = Keys.hmacShaKeyFor(bytes);
    }

    public String createAccessTokenAndRefreshToken(Authentication authResult, HttpServletResponse response) {
        String uuid = UUID.randomUUID().toString();

        String accessToken = createAccessToken(authResult, uuid);
        String refreshToken = createRefreshToken(authResult, uuid);

        response.addHeader(JwtProvider.AUTHORIZATION_HEADER, accessToken);
        response.addHeader(JwtProvider.REFRESH_AUTHORIZATION_HEADER, refreshToken);

//        TokenService.saveAuth(username, accessToken, refreshToken);

        return extractRefreshToken(refreshToken);

    }

    private String extractRefreshToken(String refreshToken) {
        return refreshToken.replace("Bearer ", "");
    }

    public String createAccessToken(Authentication authentication, String uuid) {
        Date date = new Date();

        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        return BEARER_PREFIX +
                Jwts.builder()
                        .setId(uuid) // JWT ID 설정
                        .setSubject(authentication.getName()) // 사용자 식별자값(ID) //토큰의 주제 설정
                        .claim(AUTHORIZATION_KEY, authorities) // 사용자 권한 정보 저장
                        .setIssuer(ISSUER)
                        .setIssuedAt(date) // 발급일
                        .setExpiration(new Date(date.getTime() + ACCESS_TOKEN_TIME)) // 만료 시간
                        .signWith(key, signatureAlgorithm) // 암호화 알고리즘
                        .compact();
    }

    public String createRefreshToken(Authentication authentication, String uuid) {
        Date date = new Date();

        return BEARER_PREFIX +
                Jwts.builder()
                        .setId(uuid) // JWT ID 설정
                        .setSubject(authentication.getName()) // 사용자 식별자값(ID)
                        .claim(AUTHORIZATION_KEY, authentication.getAuthorities()) // 사용자 권한 정보 저장
                        .setIssuer(ISSUER)
                        .setIssuedAt(date) // 발급일
                        .setExpiration(new Date(date.getTime() + REFRESH_TOKEN_TIME)) // 만료 시간
                        .signWith(key, signatureAlgorithm) // 암호화 알고리즘
                        .compact();
    }



}
