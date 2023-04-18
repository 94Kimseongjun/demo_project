package co.kr.ntels.demo_project.security;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

import co.kr.ntels.demo_project.redis.Redis;
import co.kr.ntels.demo_project.security.dto.Token;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.security.Keys;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider {
    private final Redis redis;

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);
    @Value("${spring.security.jwt.secret}")
    private String jwtSecret;
    @Value("${spring.security.jwt.expiration}")
    private int jwtExpirationInMs;
    @Value("${spring.security.jwt.refreshTokenExpiration}")
    private int refreshTokenExpiration;

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
                .signWith(getSignKey())
                .compact();

        String refreshToken = Jwts
                .builder()
                .setSubject(Long.toString(userPrincipal.getId()))
                .setIssuedAt(new Date())
                .setExpiration(refreshExpiryDate)
                .signWith(getSignKey())
                .compact();

        return Token.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(expiryDate)
                .refreshExpiresIn(refreshExpiryDate)
                .build();
    }

    public Long getUserIdFromJWT(String token) {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSignKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            return Long.parseLong(claims.getSubject());
    }
    public String reGenerateToken(Long userId, String oldAccessToken){

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationInMs);
        String newAccessToken = Jwts
                .builder()
                .setSubject(Long.toString(userId))
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(getSignKey())
                .compact();

        return newAccessToken;
    }

    public boolean validateToken(String authToken) {
        try {
            Jwts.parserBuilder().setSigningKey(getSignKey()).build().parseClaimsJws(authToken);
            return true;
        } catch (MalformedJwtException ex) {
            logger.error("Invalid JWT token");
        } catch (ExpiredJwtException ex) {
            logger.error("Expired JWT token");
            throw ex; // 예외 발생시켜서 refresh 토큰 검증 및 newAccessToken 생성하는 로직으로 흐름 제어
        } catch (UnsupportedJwtException ex) {
            logger.error("Unsupported JWT token");
        } catch (IllegalArgumentException ex) {
            logger.error("JWT claims string is empty.");
        }
        return false;
    }
    private Key getSignKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes(StandardCharsets.UTF_8));
    }

    // method to validate a refresh token and return its expiry date

    public Date getExpiryDate(String token) {
        try {
            Key key = getSignKey();
            Jwts.parser().setSigningKey(key).parseClaimsJws(token);
            Claims claims = Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();
            Date expiryDate = claims.getExpiration();
            return expiryDate;
        } catch (SignatureException ex) {
            // handle invalid signature
        } catch (MalformedJwtException ex) {
            // handle invalid JWT token
        } catch (ExpiredJwtException ex) {
            // handle expired JWT token
        } catch (UnsupportedJwtException ex) {
            // handle unsupported JWT token
        } catch (IllegalArgumentException ex) {
            // handle JWT token claims string is empty
        }
        return null;
    }

    public String validateRefreshToken(String token){
        String refreshToken = redis.getValueByKey(token);
        if (refreshToken!=null && !refreshToken.isEmpty()){
            return refreshToken;
        }
        return null;
    }

}
