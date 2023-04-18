package co.kr.ntels.demo_project.repository;

import co.kr.ntels.demo_project.model.Role;
import co.kr.ntels.demo_project.model.RoleName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository // 생략 가능 JpaRepository를 상속받기때문
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(RoleName roleName);
}

