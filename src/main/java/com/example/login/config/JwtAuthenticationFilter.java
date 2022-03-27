package com.example.login.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenUtil jwtTokenUtil;
    private final CustomUserDetailService customUserDetailService;
    private final LogoutAccessTokenRedisRepository logoutAccessTokenRedisRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String accessToken = getToken(request);
        if (accessToken != null) {
            checkLogout(accessToken);
            String username = jwtTokenUtil.getUsername(accessToken);
            if (username != null) {
                UserDetails userDetails = customUserDetailService.loadUserByUsername(username);
                equalsUsernameFromTokenAndUserDetails(userDetails.getUsername(), username);
                validateAccessToken(accessToken, userDetails);
                processSecurity(request, userDetails);
            }
        }
        filterChain.doFilter(request, response);
    }
    //헤더에서 Bearer라고 붙어 있으면 토큰 가져오기
    private String getToken(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");
        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }
        return null;
    }
    //로그아웃이 된 토큰 확인하기
    private void checkLogout(String accessToken) {
        if (logoutAccessTokenRedisRepository.existsById(accessToken)) {
            throw new IllegalArgumentException("이미 로그아웃된 회원입니다.");
        }
    }

    private void equalsUsernameFromTokenAndUserDetails(String userDetailsUsername, String tokenUsername) {
        if (!userDetailsUsername.equals(tokenUsername)) {
            throw new IllegalArgumentException("username이 토큰과 맞지 않습니다.");
        }
    }

    private void validateAccessToken(String accessToken, UserDetails userDetails) {
        if (!jwtTokenUtil.validateToken(accessToken, userDetails)) {
            throw new IllegalArgumentException("토큰 검증 실패");
        }
    }

    private void processSecurity(HttpServletRequest request, UserDetails userDetails) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(userDetails,null, userDetails.getAuthorities());
        usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
    }
}