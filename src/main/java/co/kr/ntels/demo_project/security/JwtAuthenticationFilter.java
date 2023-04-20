package co.kr.ntels.demo_project.security;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import co.kr.ntels.demo_project.redis.Redis;
import co.kr.ntels.demo_project.security.dto.Token;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;
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

    @Value("${spring.security.jwt.refreshSecret}")
    private String refreshSecret;

    @Value("${spring.security.jwt.secret}")
    private String jwtSecret;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String jwt = getJwtFromRequest(request);
       try {
           if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt,jwtSecret)){
               Long userId = tokenProvider.getUserIdFromJWT(jwt,jwtSecret);
               setAuthenticationInContext(userId, request);
           }
       } catch (ExpiredJwtException e){
           String refreshToken = tokenProvider.validateRefreshToken(jwt);
           if (refreshToken != null) { // refresh Token이 redis에 저장되어있음
               Long userId = tokenProvider.getUserIdFromJWT(refreshToken, refreshSecret); // refreshToken 에서 userId 추출

               Token newToken = tokenProvider.reGenerateToken(userId);
               String newAccessToken = newToken.getAccessToken();
               String newRefreshToken = newToken.getRefreshToken();

               response.setHeader("Authorization", "Bearer " + newAccessToken); // header에 새 access Token 삽입

               redis.deleteByKey(jwt); // redis 기존 값 삭제
               redis.deleteByKey(refreshToken);
               redis.setRedis(newAccessToken,newRefreshToken,refreshTokenExpiration);   // redis에 새로 넣어주기
               redis.setRedis(newRefreshToken,newAccessToken,refreshTokenExpiration);
               setAuthenticationInContext(userId, request);
           }
       } catch (SignatureException e){
           redis.deleteByKey(redis.getValueByKey(jwt));
           redis.deleteByKey(jwt);
       }

        filterChain.doFilter(request, response);
    }

    private void setAuthenticationInContext(Long userId, HttpServletRequest request){
        UserDetails userDetails = customUserDetailsService.loadUserById(userId);
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7, bearerToken.length());
        }
        return null;
    }
}