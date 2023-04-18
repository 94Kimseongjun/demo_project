package co.kr.ntels.demo_project.controller;

import co.kr.ntels.demo_project.dto.*;
import co.kr.ntels.demo_project.exception.AppException;

import co.kr.ntels.demo_project.model.Role;
import co.kr.ntels.demo_project.model.RoleName;
import co.kr.ntels.demo_project.model.User;
import co.kr.ntels.demo_project.redis.Redis;
import co.kr.ntels.demo_project.repository.RoleRepository;
import co.kr.ntels.demo_project.repository.UserRepository;
import co.kr.ntels.demo_project.security.JwtTokenProvider;
import co.kr.ntels.demo_project.security.dto.Token;
import co.kr.ntels.demo_project.util.PasswordValidator;
import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Value;


import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import javax.validation.Valid;

import java.time.LocalDateTime;
import java.util.Collections;


import org.springframework.transaction.annotation.Transactional;


@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;
    private final PasswordValidator passwordValidator;

    private final Redis redis;

    @Value("${spring.security.jwt.refreshTokenExpiration}")
    private int refreshTokenExpiration;

    @Transactional
    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsernameOrEmail(),
                        loginRequest.getPassword()
                )
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        Token jwt = tokenProvider.generateToken(authentication);

        User user = userRepository.findByUsernameOrEmail(loginRequest.getUsernameOrEmail(), loginRequest.getUsernameOrEmail())
                .orElseThrow(() -> new UsernameNotFoundException("유저를 찾을 수 없습니다."));

        LocalDateTime now = LocalDateTime.now();
        userRepository.updateLastLoginAt(now, user.getId());

        boolean passwordUpdateRequired = user.getPasswordUpdateAt().plusDays(90).isBefore(now);

        //redisTemplate.opsForValue().set(jwt.getAccessToken(), jwt.getRefreshToken(), refreshTokenExpiration, TimeUnit.MILLISECONDS);

        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + jwt.getAccessToken());
        redis.setRedis(jwt.getAccessToken(), jwt.getRefreshToken(), refreshTokenExpiration);

        return ResponseEntity.ok().headers(headers).body(new LoginResponse(passwordUpdateRequired));

    }


    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
        if(userRepository.existsByUsername(signUpRequest.getUsername())) {
            return new ResponseEntity(new ApiResponse(false, "username이 이미 존재 합니다."),
                    HttpStatus.BAD_REQUEST);
        }
        if(userRepository.existsByEmail(signUpRequest.getEmail())) {
            return new ResponseEntity(new ApiResponse(false, "Email이 이미 존재 합니다."),
                    HttpStatus.BAD_REQUEST);
        }
        // 비밀번호 규칙 검증
        if(!passwordValidator.validate(signUpRequest.getPassword(), signUpRequest.getUsername())) {
            return new ResponseEntity(new ApiResponse(false,
                    "비밀번호는 소문자, 대문자, 숫자, 특수 문자를 모두 포함 해야 하며 길이는 8~30자 여야 합니다. " +
                            "또한 연속된 문자 또는 숫자, 연속된 키보드 배열은 사용할 수 없습니다. "),
                    HttpStatus.BAD_REQUEST);
        }
        // Creating user's account
        User user = new User(signUpRequest.getName(), signUpRequest.getUsername(),
                signUpRequest.getEmail(), signUpRequest.getPassword(), LocalDateTime.now(), null);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        Role userRole = roleRepository.findByName(RoleName.ROLE_USER)
                .orElseThrow(() -> new AppException("User Role not set."));
        user.setRoles(Collections.singleton(userRole));
        userRepository.save(user);

        /*
        User result = userRepository.save(user);
        URI location = ServletUriComponentsBuilder
                .fromCurrentContextPath().path("/api/users/{username}")
                .buildAndExpand(result.getUsername()).toUri();
        return ResponseEntity.created(location).body(new ApiResponse(true, "회원가입이 성공적으로 완료 되었습니다."));
         */

        return ResponseEntity.ok().body((new ApiResponse(true, "회원가입이 성공적으로 완료 되었습니다.")));
    }

    @GetMapping("/check/username")
    public ResponseEntity<?> existsByUsername(@Valid @RequestBody CheckUsernameRequest checkUsernameRequest){
        if(userRepository.existsByUsername(checkUsernameRequest.getUsername())){
            return new ResponseEntity<>(new ApiResponse(false, "해당 username이 이미 존재 합니다."),
                    HttpStatus.BAD_REQUEST);
        }
        return ResponseEntity.ok().body(new ApiResponse(true, "사용가능한 username 입니다."));
    }

    @GetMapping("/check/email")
    public ResponseEntity<?> existsByEmail(@Valid @RequestBody CheckEmailRequest checkEmailRequest){
        if(userRepository.existsByEmail(checkEmailRequest.getEmail())){
            return new ResponseEntity<>(new ApiResponse(false, "해당 Email이 이미 존재 합니다."),
                    HttpStatus.BAD_REQUEST);
        }
        return ResponseEntity.ok().body(new ApiResponse(true, "사용가능한 Email 입니다."));
    }

    /*
    @GetMapping("/check/usernameOrEmail")
    public ResponseEntity<?> existByusernameOrEmail(@Valid @RequestBody CheckUsernameOrEmail checkUsernameOrEmail){
        if(userRepository.existByUsernameOrEmail(checkUsernameOrEmail.getUsernameOrEmail(), checkUsernameOrEmail.getUsernameOrEmail())){
            return new ResponseEntity<>(new ApiResponse(false,"해당 username 또는 Email이 이미 존재 합니다."),HttpStatus.BAD_REQUEST);
        }
        return ResponseEntity.ok().body(new ApiResponse(true,"사용가능합니다."));
    }
     */
}

