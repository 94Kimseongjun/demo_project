package co.kr.ntels.demo_project.controller;

import co.kr.ntels.demo_project.dto.*;
import co.kr.ntels.demo_project.exception.ResourceNotFoundException;

import co.kr.ntels.demo_project.model.Role;
import co.kr.ntels.demo_project.model.RoleName;
import co.kr.ntels.demo_project.model.User;
import co.kr.ntels.demo_project.repository.UserRepository;
import co.kr.ntels.demo_project.security.CurrentUser;
import co.kr.ntels.demo_project.security.UserPrincipal;
import co.kr.ntels.demo_project.util.PasswordValidator;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.time.LocalDateTime;
import java.util.List;
import org.springframework.data.domain.Page;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordValidator passwordValidator;

    @GetMapping("/me")
    public UserResponse getCurrentUser(@CurrentUser UserPrincipal currentUser) {
        if(currentUser == null) {
            throw new AccessDeniedException("You are not authorized to access this resource.");
        }
        UserResponse userResponse = new UserResponse(currentUser.getId(), currentUser.getUsername(),
                currentUser.getName(), currentUser.getEmail(),null,null,null,null);
        User user = userRepository.findById(currentUser.getId()).orElseThrow(() -> new ResourceNotFoundException("User", "id", currentUser.getId()));
        userResponse.setLastLoginAt(user.getLastLoginAt());
        userResponse.setCreatedAt(user.getCreatedAt());
        userResponse.setUpdatedAt(user.getUpdatedAt());
        userResponse.setPasswordUpdateAt(user.getPasswordUpdateAt());

        return userResponse;
    }

    // 자신의 정보 수정
    @PutMapping("/me")
    @Transactional
    public ResponseEntity<?> updateUser(@CurrentUser UserPrincipal currentUser, @Valid @RequestBody UpdateUserRequest updateUserRequest) {
        // 사용자 인증 확인
        if (!currentUser.getId().equals(updateUserRequest.getId())) {
            return ResponseEntity.badRequest().body(new ApiResponse(false, "잘못된 사용자입니다."));
        }

        // User 엔티티를 DB에서 조회하고, 업데이트
        User user = userRepository.findById(currentUser.getId()).orElseThrow(() -> new ResourceNotFoundException("User", "id", currentUser.getId()));
        if (updateUserRequest.getName() != null && !updateUserRequest.getName().isEmpty() && !updateUserRequest.getName().equals(user.getName())) {
            user.setName(updateUserRequest.getName());
        }

        if (updateUserRequest.getEmail() != null && !updateUserRequest.getEmail().isEmpty() && !updateUserRequest.getEmail().equals(user.getEmail())){
            if(userRepository.existsByEmail(updateUserRequest.getEmail())){
                return new ResponseEntity<>(new ApiResponse(false, "해당 Email이 이미 존재 합니다."), HttpStatus.BAD_REQUEST);
            }
            user.setEmail(updateUserRequest.getEmail());
        }

        if (updateUserRequest.getUsername() != null && !updateUserRequest.getUsername().isEmpty() && !updateUserRequest.getUsername().equals(user.getUsername())){
            if(userRepository.existsByUsername(updateUserRequest.getUsername())){
                return new ResponseEntity<>(new ApiResponse(false, "해당 username이 이미 존재 합니다."), HttpStatus.BAD_REQUEST);
            }
            user.setUsername(updateUserRequest.getUsername());
        }

        if (updateUserRequest.getCurrentPassword() != null && !updateUserRequest.getCurrentPassword().isEmpty() && updateUserRequest.getNewPassword() != null && !updateUserRequest.getNewPassword().isEmpty()) {
            // 현재 비밀번호 확인
            if (!passwordEncoder.matches(updateUserRequest.getCurrentPassword(), user.getPassword())) {
                return ResponseEntity.badRequest().body(new ApiResponse(false, "현재 비밀번호가 일치하지 않습니다."));
            }
            // 새로운 비밀번호 확인
            if (updateUserRequest.getCurrentPassword().equals(updateUserRequest.getNewPassword())) {
                return ResponseEntity.badRequest().body(new ApiResponse(false, "새로운 비밀번호는 현재 비밀번호와 같을 수 없습니다."));
            }
            // 새로운 비밀번호 규칙 검증
            if(!passwordValidator.validate(updateUserRequest.getNewPassword(), updateUserRequest.getUsername())) {
                return new ResponseEntity<>(new ApiResponse(false,
                    "비밀번호는 소문자, 대문자, 숫자, 특수 문자를 모두 포함 해야 하며 길이는 8~30자 여야 합니다."), HttpStatus.BAD_REQUEST);
            }
            // 새로운 비밀번호 업데이트
            user.setPassword(passwordEncoder.encode(updateUserRequest.getNewPassword()));
            user.setPasswordUpdateAt(LocalDateTime.now());
        }
        userRepository.save(user);
        return ResponseEntity.ok().body(new ApiResponse(true, "사용자 정보가 성공적으로 업데이트 되었습니다."));
    }

    @DeleteMapping("/me")
    @Transactional
    public ResponseEntity<?> deleteUser(@CurrentUser UserPrincipal currentUser) {
        userRepository.deleteById(currentUser.getId());
        return ResponseEntity.ok().body(new ApiResponse(true,"탈퇴 되었습니다."));
    }

    @Transactional
    @PutMapping("/me/passwordUpdateAt")
    public ResponseEntity<?> updatePasswordUpdateAt(@CurrentUser UserPrincipal currentUser){
        User user = userRepository.findById(currentUser.getId())
                .orElseThrow(() -> new UsernameNotFoundException("유저를 찾을 수 없습니다."));
        userRepository.updatePasswordUpdateAt(LocalDateTime.now(), user.getId());
        return ResponseEntity.ok().body(new ApiResponse(true,"마지막 비밀번호 수정일이 성공적으로 업데이트 되었습니다."));
    }

    @GetMapping("/all")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<?> findAllUsers(@CurrentUser UserPrincipal currentUser,
                                          @RequestParam(defaultValue = "0") int page,
                                          @RequestParam(defaultValue = "10") int size,
                                          @RequestParam(defaultValue = "id") String sort,
                                          @RequestParam(defaultValue = "asc") String direction) {
        Pageable pageable = direction.equals("desc") ? PageRequest.of(page, size, Sort.by(sort).descending()) : PageRequest.of(page, size, Sort.by(sort).ascending());
        Page<User> users = userRepository.findAll(pageable);
        List<UserResponse> userResponses = users.getContent().stream()
                .map(user -> new UserResponse(user.getId(), user.getUsername(), user.getName(), user.getEmail(), user.getCreatedAt(), user.getUpdatedAt(), user.getPasswordUpdateAt(), user.getLastLoginAt()))
                .collect(Collectors.toList());
        return ResponseEntity.ok(userResponses);
    }

    @PutMapping("/other")
    @Transactional
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<?> updateUserById(@Valid @RequestBody UpdateUserRequest updateUserRequest) {
        User user = userRepository.findById(updateUserRequest.getId()).orElseThrow(() -> new ResourceNotFoundException("User", "id", updateUserRequest.getId()));

        /*
        for(Role role: user.getRoles()){
            if(role.getName() == RoleName.ROLE_ADMIN){
                return ResponseEntity.badRequest().body(new ApiResponse(false, "다른 ADMIN 의 정보를 수정 할 수 없습니다."));
            }
        }
         */

        if (user.getRoles().stream().anyMatch(role -> role.getName() == RoleName.ROLE_ADMIN)) {
            return ResponseEntity.badRequest().body(new ApiResponse(false, "다른 ADMIN 의 정보를 수정 할 수 없습니다."));
        }

        if (updateUserRequest.getName() != null && !updateUserRequest.getName().isEmpty() && !updateUserRequest.getName().equals(user.getName())) {
            user.setName(updateUserRequest.getName());
        }

        if (updateUserRequest.getEmail() != null && !updateUserRequest.getEmail().isEmpty() && !updateUserRequest.getEmail().equals(user.getEmail())){
            if(userRepository.existsByEmail(updateUserRequest.getEmail())){
                return new ResponseEntity<>(new ApiResponse(false, "해당 Email이 이미 존재 합니다."), HttpStatus.BAD_REQUEST);
            }
            user.setEmail(updateUserRequest.getEmail());
        }

        if (updateUserRequest.getUsername() != null && !updateUserRequest.getUsername().isEmpty() && !updateUserRequest.getUsername().equals(user.getUsername())){
            if(userRepository.existsByUsername(updateUserRequest.getUsername())){
                return new ResponseEntity<>(new ApiResponse(false, "해당 username이 이미 존재 합니다."), HttpStatus.BAD_REQUEST);
            }
            user.setUsername(updateUserRequest.getUsername());
        }

        if (updateUserRequest.getNewPassword() != null && !updateUserRequest.getNewPassword().isEmpty()) {
            // 새로운 비밀번호 규칙 검증
            if(!passwordValidator.validate(updateUserRequest.getNewPassword(), updateUserRequest.getUsername())) {
                return new ResponseEntity<>(new ApiResponse(false,
                    "비밀번호는 소문자, 대문자, 숫자, 특수 문자를 모두 포함 해야 하며 길이는 8~30자 여야 합니다."), HttpStatus.BAD_REQUEST);
            }
            // 새로운 비밀번호 업데이트
            user.setPassword(passwordEncoder.encode(updateUserRequest.getNewPassword()));
            user.setPasswordUpdateAt(LocalDateTime.now());
        }
        userRepository.save(user);
        return ResponseEntity.ok().body(new ApiResponse(true, "사용자 정보가 성공적으로 업데이트 되었습니다."));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }
        return ResponseEntity.ok().body(new ApiResponse(true, "로그아웃 되었습니다."));
    }

}


/*
 boolean isAdmin = currentUser.getAuthorities().stream()
                .anyMatch(role -> role.getAuthority().equals(RoleName.ROLE_ADMIN.name()));
        if (!isAdmin) {
            return ResponseEntity.badRequest().body(new ApiResponse(false, "권한이 없습니다."));
 */