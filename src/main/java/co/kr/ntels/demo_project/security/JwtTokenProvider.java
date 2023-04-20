package co.kr.ntels.demo_project.security;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import co.kr.ntels.demo_project.redis.Redis;
import co.kr.ntels.demo_project.security.dto.Token;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.security.Keys;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtTokenProvider {
    private final Redis redis;

    @Value("${spring.security.jwt.secret}")
    private String jwtSecret;
    @Value("${spring.security.jwt.expiration}")
    private int jwtExpirationInMs;
    @Value("${spring.security.jwt.refreshTokenExpiration}")
    private int refreshTokenExpiration;

    @Value("${spring.security.jwt.refreshSecret}")
    private String refreshSecret;

    private final RedisTemplate<String, Object> redisTemplate;

    public Token generateToken(Authentication authentication) {

        UserPrincipal userPrincipal = (UserPrincipal)authentication.getPrincipal();

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationInMs);
        Date refreshExpiryDate = new Date(now.getTime() + refreshTokenExpiration);

        String accessToken = Jwts
                .builder()
                .setSubject(Long.toString(userPrincipal.getId()))
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(getSignKey(jwtSecret))
                .compact();

        String refreshToken = Jwts
                .builder()
                .setSubject(Long.toString(userPrincipal.getId()))
                .setIssuedAt(new Date())
                .setExpiration(refreshExpiryDate)
                .signWith(getSignKey(refreshSecret))
                .compact();

        return Token.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(expiryDate)
                .refreshExpiresIn(refreshExpiryDate)
                .build();
    }

    public Long getUserIdFromJWT(String token, String secret) {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSignKey(secret))
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            return Long.parseLong(claims.getSubject());
    }
    public Token reGenerateToken(Long userId){

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationInMs);
        Date refreshExpiryDate = new Date(now.getTime() + refreshTokenExpiration);
        String newAccessToken = Jwts
                .builder()
                .setSubject(Long.toString(userId))
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(getSignKey(jwtSecret))
                .compact();

        String newRefreshToken = Jwts
                .builder()
                .setSubject(Long.toString(userId))
                .setIssuedAt(new Date())
                .setExpiration(refreshExpiryDate)
                .signWith(getSignKey(refreshSecret))
                .compact();

        return Token.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .expiresIn(expiryDate)
                .refreshExpiresIn(refreshExpiryDate)
                .build();
    }

    public boolean validateToken(String authToken, String secret) {
        try {
            Jwts.parserBuilder().setSigningKey(getSignKey(secret)).build().parseClaimsJws(authToken);
            return true;
        } catch (MalformedJwtException ex) {
            log.error("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            log.error("Expired JWT token");
            throw ex; // 예외 발생시켜서 refresh 토큰 검증 및 newAccessToken 생성하는 로직으로 흐름 제어
        } catch (UnsupportedJwtException ex) {
            log.error("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            log.error("JWT claims string is empty.");
        } catch (SignatureException ex) {
            log.error("JWT signature does not match locally computed signature.");
            throw ex; // 위조 및 탈취 가능성, 들어온 key 관련 redis 데이터 모두 삭제

        }
        return false;
    }
    private Key getSignKey(String secret) {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public String validateRefreshToken(String token){
        String refreshToken = redis.getValueByKey(token);
        if (refreshToken!=null && !refreshToken.isEmpty()){
            return refreshToken;
        }
        log.info("Redis not found Key");
        return null;
    }

}
