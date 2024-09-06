package study.jwt.common.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import study.jwt.common.filter.JwtAuthenticationFilter;
import study.jwt.common.filter.JwtAuthorizationFilter;
import study.jwt.common.security.auth.AuthUserService;
import study.jwt.common.security.handler.CustomLoginFailureHandler;
import study.jwt.common.security.handler.JwtAccessDenyHandler;
import study.jwt.common.security.handler.JwtAuthenticationEntryPoint;
import study.jwt.common.security.jwt.JwtProvider;
import study.jwt.domain.user.repository.UserRepository;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final String ADMIN = "ADMIN";
    private final String Version = "/v1";

    private final JwtProvider jwtProvider;
    private final ObjectMapper objectMapper;
    private final UserRepository userRepository;
    private final AuthUserService authUserService;
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDenyHandler jwtAccessDenyHandler;


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() throws Exception {
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwtProvider, userRepository, objectMapper);
        filter.setAuthenticationManager(authenticationManager(authenticationConfiguration));
        return filter;
    }

    @Bean
    public JwtAuthorizationFilter jwtAuthorizationFilter() {
        return new JwtAuthorizationFilter(jwtProvider,userRepository, authUserService);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(AbstractHttpConfigurer::disable);

        http.sessionManagement((sessionManagement) ->
                sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );

        http.formLogin(form -> form
                .loginPage("/login")
                .permitAll()
                .defaultSuccessUrl("", true)
                .failureHandler(new CustomLoginFailureHandler())
                .permitAll()
        );


        http.authorizeHttpRequests((authorizeHttpRequests) -> authorizeHttpRequests
                .requestMatchers(HttpMethod.GET,Version + "/public/**").permitAll()
                .requestMatchers(Version + "/admin/**").hasRole(ADMIN)
                .anyRequest().authenticated()
        );

        http.addFilterAfter(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);//로그인시
        http.addFilterBefore(jwtAuthorizationFilter(), UsernamePasswordAuthenticationFilter.class);//데이터요청시

        http.exceptionHandling(exceptionHandling -> exceptionHandling
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDenyHandler)
        );

        return http.build();
    }

}
