package co.kr.ntels.demo_project.security;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.*;
import java.util.stream.Collectors;

import co.kr.ntels.demo_project.model.Role;
import co.kr.ntels.demo_project.redis.Redis;
import co.kr.ntels.demo_project.security.dto.Token;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;


import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.GrantedAuthority;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import co.kr.ntels.demo_project.model.User;

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
//List<String> authorities = userPrincipal.getAuthorities().stream()
        //        .map(GrantedAuthority::getAuthority)
        //        .collect(Collectors.toList());

        UserPrincipal userPrincipal = (UserPrincipal)authentication.getPrincipal();

        String username = userPrincipal.getUsername();
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationInMs);
        Date refreshExpiryDate = new Date(now.getTime() + refreshTokenExpiration);

        Map<String, Object> claims = new HashMap<>();
        claims.put("authorities", authorities);
        //claims.put("username", username);
        log.info("TOKEN CREATE, USER_ID -> " + userPrincipal.getId());

        String accessToken = Jwts
                .builder()
                .setSubject(Long.toString(userPrincipal.getId()))
                .addClaims(claims)
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(getSignKey(jwtSecret))
                .compact();

        String refreshToken = Jwts
                .builder()
                .setSubject(Long.toString(userPrincipal.getId()))
                .claim("authorities", authorities)
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
            log.info("GET USER_ID ->" + claims.getSubject());
            return Long.parseLong(claims.getSubject());
    }
    public Token reGenerateToken(Long userId, Authentication authentication){
        UserPrincipal userPrincipal = (UserPrincipal)authentication.getPrincipal();

        List<String> authorities = userPrincipal.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpirationInMs);
        Date refreshExpiryDate = new Date(now.getTime() + refreshTokenExpiration);
        String newAccessToken = Jwts
                .builder()
                .setSubject(Long.toString(userId))
                .claim("authorities", authorities)
                .setIssuedAt(new Date())
                .setExpiration(expiryDate)
                .signWith(getSignKey(jwtSecret))
                .compact();

        String newRefreshToken = Jwts
                .builder()
                .setSubject(Long.toString(userId))
                .claim("authorities", authorities)
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

    public List<String> getAuthoritiesFromToken(String jwt){
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSignKey(jwtSecret))
                .build()
                .parseClaimsJws(jwt)
                .getBody();

        return (List<String>) claims.get("authorities");
    }

    public UsernamePasswordAuthenticationToken getAuthenticationFromJWT(String token, Long userId) {
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(getSignKey(jwtSecret))
                .build()
                .parseClaimsJws(token)
                .getBody();

        // 클레임에서 권한 정보 가져오기
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("authorities").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());
        //String username = (String) claims.get("username");
        // UserDetails 객체를 만들어서 Authentication 리턴
        /*
            public User(String name, String username, String email, String password, LocalDateTime passwordUpdateAt, LocalDateTime lastLoginAt) {
        this.name = name;
        this.username = username;
        this.email = email;
        this.password = password;
        this.passwordUpdateAt = passwordUpdateAt;
        this.lastLoginAt = lastLoginAt;
    }
         */

        User user = new User(null, null, null,null,null,null);
        //user.setUsername(username);
        user.setId(userId);
        //List<String> rolesList = Arrays.asList(claims.get("authorities").toString().split(","));
        //Set<Role> roles = rolesList.stream().map(Role::new).collect(Collectors.toSet());
        //user.setRoles(roles);
        UserDetails principal = UserPrincipal.create(user);

        return new UsernamePasswordAuthenticationToken(principal, "", authorities);

    }









}
