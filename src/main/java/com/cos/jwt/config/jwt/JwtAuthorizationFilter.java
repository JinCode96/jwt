package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.Users;
import com.cos.jwt.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;

/**
 * 인가
 * 시큐리티가 BasicAuthenticationFilter 라는 필터를 가지고 있는데,
 * 권한이나 인증이 필요한 특정 주소를 요청했을 때 이 필터를 거치게 된다.
 * 권한, 인증이 필요없는 주소라면 이 필터를 거치지 않는다.
 */
@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private final UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        log.info("권한 인증이 필요한 주소로 진입!!!");

        String header = request.getHeader(JwtProperties.HEADER_STRING);

        // header 가 있는지 확인
        if (header == null || !header.startsWith(JwtProperties.TOKEN_PREFIX)) {
            chain.doFilter(request, response);
            log.info("권한 인증되지 않음!!!");
            return; // 리다이렉트로 보낼 수도 있다.
        }

        // Bearer 지우고 토큰 값만 남기기
        String token = request
                .getHeader(JwtProperties.HEADER_STRING)
                .replace(JwtProperties.TOKEN_PREFIX, "");
        log.info("token={}", token);

        /*
            토큰 검증 (이게 인증이기 때문에 AuthenticationManager 도 필요 없음)
            내가 SecurityContext 에 집적접근해서 세션을 만들때 자동으로 UserDetailsService 에 있는
            loadByUsername 이 호출됨.
        */
        String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET))
                    .build()
                    .verify(token) // 서명
                    .getClaim("username") // username 을 가져올 거다.
                    .asString(); // String 으로 캐스팅

        log.info("토큰 검증 완료!!! username={}", username);

        // 서명이 정상적으로 됐다면
        if (username != null) {
            Users userEntity = userRepository.findByUsername(username); // DB 연결하여 정상적인 사용자인지 확인

            // 인증은 토큰 검증시 끝. 인증을 하기 위해서가 아닌 스프링 시큐리티가 수행해주는 권한 처리를 위해
            // 아래와 같이 토큰을 만들어서 Authentication 객체를 강제로 만들고 그걸 세션에 저장!
            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                                principalDetails, // 나중에 컨트롤러에서 DI 해서 쓸 때 사용하기 편함.
                                null, // 패스워드는 모르니까 null 처리, 어차피 지금 인증하는게 아니니까!!
                                principalDetails.getAuthorities());

            // 강제로 시큐리티 세션에 접근하여 값 저장
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        chain.doFilter(request, response);
    }
}
