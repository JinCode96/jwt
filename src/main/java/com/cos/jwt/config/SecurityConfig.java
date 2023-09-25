package com.cos.jwt.config;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.config.jwt.JwtAuthorizationFilter;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Slf4j
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserRepository userRepository;
    private final CorsConfig corsConfig;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        log.info("filterChain...");

        http.csrf(AbstractHttpConfigurer::disable);

        http
                // jwt 기본 세팅
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 이 서버는 세션을 사용하지 않겠다. stateless 로 만들겠다.
                .formLogin(login -> login.disable()) // 폼 로그인 사용 x
                .httpBasic(config -> config.disable()) // http 로그인 방식 사용 x
                .apply(new MyCustomDsl()); // 필터 사용

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(AntPathRequestMatcher.antMatcher("/api/v1/user/**")).hasAnyRole("USER", "MANAGER", "ADMIN")
                        .requestMatchers(AntPathRequestMatcher.antMatcher("/api/v1/manager/**")).hasAnyRole("MANAGER", "ADMIN")
                        .requestMatchers(AntPathRequestMatcher.antMatcher("/api/v1/admin/**")).hasAnyRole("ADMIN")
                        .anyRequest().permitAll()
                );

        return http.build();
    }

    public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {
        @Override
        public void configure(HttpSecurity http) throws Exception {
            log.info("MyCustomDsl...");
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            http
                    .addFilter(corsConfig.corsFilter())
                    .addFilter(new JwtAuthenticationFilter(authenticationManager)) // 인증 (이 필터를 추가해주어야 /login 진행)
                    .addFilter(new JwtAuthorizationFilter(authenticationManager, userRepository)); // 인가
        }
    }

}
