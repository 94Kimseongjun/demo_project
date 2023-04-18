package co.kr.ntels.demo_project.security;

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
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
    private final RedisTemplate<String, Object> redisTemplate;
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Value("${spring.security.jwt.refreshTokenExpiration}")
    private int refreshTokenExpiration;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String jwt = getJwtFromRequest(request);
        Long userId = tokenProvider.getUserIdFromJWT(jwt);
        if (StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)){
            UserDetails userDetails = customUserDetailsService.loadUserById(userId);
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        filterChain.doFilter(request, response);
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