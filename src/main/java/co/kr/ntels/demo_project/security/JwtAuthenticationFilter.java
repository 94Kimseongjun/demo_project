package co.kr.ntels.demo_project.security;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Date;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import co.kr.ntels.demo_project.redis.Redis;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtTokenProvider tokenProvider;
    private final CustomUserDetailsService customUserDetailsService;

    private final Redis redis;
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Value("${spring.security.jwt.refreshTokenExpiration}")
    private int refreshTokenExpiration;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String jwt = getJwtFromRequest(request);
       try {
           if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)){
               Long userId = tokenProvider.getUserIdFromJWT(jwt);
               setAuthenticationInContext(userId, request);
//               UserDetails userDetails = customUserDetailsService.loadUserById(userId);
//               UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
//               authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//               SecurityContextHolder.getContext().setAuthentication(authentication);
           }
       } catch (ExpiredJwtException e){
           String refreshToken = tokenProvider.validateRefreshToken(jwt);
           if (refreshToken != null) { // refresh Token이 redis에 저장되어있음
               Long userId = tokenProvider.getUserIdFromJWT(refreshToken); // refreshToken 에서 userId 추출
               String newAccessToken = tokenProvider.reGenerateToken(userId, jwt);  // 새 access Token 생성
               Date now = new Date();
               Date expiryDate = tokenProvider.getExpiryDate(refreshToken);
               long differenceInMillis = expiryDate.getTime() - now.getTime();
               response.setHeader("Authorization", "Bearer " + newAccessToken); // header에 새 access Token 삽입
               // redis 기존 값 삭제
               // redis에 새로 넣어주기
               redis.deleteByKey(jwt);
               redis.setRedis(newAccessToken,refreshToken,(int)differenceInMillis);
               logger.info("Redis New AccessToken Set Time:" + differenceInMillis);
               setAuthenticationInContext(userId, request);
//               UserDetails userDetails = customUserDetailsService.loadUserById(userId);
//               UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
//               authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
//               SecurityContextHolder.getContext().setAuthentication(authentication);

           }
       }

        filterChain.doFilter(request, response);
    }


    private void setAuthenticationInContext(Long userId, HttpServletRequest request){
        UserDetails userDetails = customUserDetailsService.loadUserById(userId);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    /*

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String jwt = getJwtFromRequest(request);
        Long userId = null;
        String newAccessToken = null;
        boolean accessToken = false;
        String refreshToken = null;
        try{
            userId = tokenProvider.getUserIdFromJWT(jwt);
            if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)){
                accessToken = true;
            }
        } catch (ExpiredJwtException e){
            // refreshToken 확인
            refreshToken = (String) redisTemplate.opsForValue().get(jwt);
            if (refreshToken != null) {
                userId = tokenProvider.getUserIdFromJWT(refreshToken);
                newAccessToken = tokenProvider.reGenerateToken(userId);
            }
        }

        if ((userId != null && accessToken) || newAccessToken != null) {
            UserDetails userDetails = customUserDetailsService.loadUserById(userId);
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        if (newAccessToken != null){
            response.setHeader("Authorization", "Bearer " + newAccessToken);
            redisTemplate.delete(jwt);
            redisTemplate.opsForValue().set(newAccessToken, refreshToken, refreshTokenExpiration, TimeUnit.MILLISECONDS);
            logger.info("New Access Token Create!");
        }

        filterChain.doFilter(request, response);
    }

     */


    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7, bearerToken.length());
        }
        return null;
    }
}