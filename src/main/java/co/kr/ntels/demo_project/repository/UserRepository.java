package co.kr.ntels.demo_project.repository;

import co.kr.ntels.demo_project.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);

    Optional<User> findByUsernameOrEmail(String username, String email);

    List<User> findByIdIn(List<Long> userIds);

    Optional<User> findByUsername(String username);

    //Boolean existByUsernameOrEmail(String username, String email);

    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);

    @Modifying
    @Query("UPDATE User u SET u.lastLoginAt = :lastLoginAt WHERE u.id = :id")
    int updateLastLoginAt(@Param("lastLoginAt") LocalDateTime lastLoginAt, @Param("id") Long id);

    @Modifying
    @Query("UPDATE User u SET u.passwordUpdateAt = :passwordUpdateAt WHERE u.id = :id")
    void updatePasswordUpdateAt(@Param("passwordUpdateAt") LocalDateTime passwordUpdateAt, @Param("id") Long id);
}

