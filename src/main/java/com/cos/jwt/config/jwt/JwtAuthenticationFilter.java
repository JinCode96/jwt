package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.dto.LoginRequestDTO;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.Date;

/**
 * 스프링 시큐리티의 UsernamePasswordAuthenticationFilter
 * /login 요청해서 username, password 를 POST 전송하면
 * UsernamePasswordAuthenticationFilter 가 동작한다.
 */

/**
 * 1. username, password 를 받아서 정상인지 로그인 시도
 * 2. authenticationManager 로 로그인 시도를 하면
 * 3. PrincipalDetailsService 의 loadByUsername 이 호출이 된다.
 * 4. return 된 PrincipalDetails 를 session 에 담고 (세션에 있어야 권한 관리를 할 수 있다.)
 * 5. JWT 토큰을 만들어 응답한다.
 */
@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager; // 이것을 통해서 로그인을 진행

    /**
     * Authentication 객체 만들어서 리턴 => 의존 : AuthenticationManager
     * 인증 요청시에 실행되는 함수 => /login
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        log.info("Jwt인증 : 진입");

        // request 에 있는 json 데이터 username 과 password 를 파싱해서 자바 Object 로 받기
        /*
        // JSON 으로 왔을 때
        ObjectMapper om = new ObjectMapper();
        LoginRequestDTO loginRequestDto = null;

        try {
            loginRequestDto = om.readValue(request.getInputStream(), LoginRequestDTO.class);
        } catch (Exception e) {
            e.printStackTrace();
        }
        */

        LoginRequestDTO loginRequestDto = new LoginRequestDTO();
        loginRequestDto.setUsername(request.getParameter("username"));
        loginRequestDto.setPassword(request.getParameter("password"));

        log.info("loginRequestDto={}", loginRequestDto);

        // 유저네임패스워드 토큰 생성
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(loginRequestDto.getUsername(), loginRequestDto.getPassword());
        log.info("토큰 생성 완료={}", authenticationToken);

        /*
            authenticate() 함수가 호출 되면 인증 프로바이더가 UserDetailsService 의
            loadUserByUsername(토큰의 첫번째 파라메터) 를 호출하고
            UserDetails 를 리턴받아서 토큰의 두번째 파라메터(credential)과
            UserDetails(DB값)의 getPassword()함수로 비교해서 동일하면
            Authentication 객체를 만들어서 필터체인으로 리턴해준다.

            Tip: 인증 프로바이더의 디폴트 서비스는 UserDetailsService 타입
            Tip: 인증 프로바이더의 디폴트 암호화 방식은 BCryptPasswordEncoder
            결론은 인증 프로바이더에게 알려줄 필요가 없음.
        */
        Authentication authentication = authenticationManager.authenticate(authenticationToken); // user 를 찾고 반환. 로그인한 정보가 담김
        log.info("authentication={}", authentication);

        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        log.info("로그인 완료됨={}", principalDetails.getUsername());

        return authentication; // 로그인 정보가 세션에 저장 (세션 사용 이유 : 권한 관리를 시큐리티가 해주기때문에 편하려고)
    }

    /**
     * attemptAuthentication() 함수가 정상 실행된 후에 실행되는 함수
     * JWT Token 생성해서 response 에 담아주기
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult)
            throws IOException, ServletException {

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // 토큰 생성
        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME)) // 만료시간 (현재 시간 + 10일정도..)
                .withClaim("id", principalDetails.getUser().getId()) // 비공개 클레임
                .withClaim("username", principalDetails.getUser().getUsername()) // 비공개 클레임
                .sign(Algorithm.HMAC512(JwtProperties.SECRET)); // 서버만 알고있는 시크릿 값 (cos)

        log.info("jwtToken={}", jwtToken);

        // 토큰 헤더에 담기
        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken); // Authorization, Bearer + jwtToken
    }
}
