package co.kr.ntels.demo_project.model;

import co.kr.ntels.demo_project.audit.BaseEntity;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.NaturalId;
import javax.persistence.Entity;
import javax.persistence.Table;
import javax.persistence.Id;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Column;
import javax.persistence.ManyToMany;
import javax.persistence.JoinTable;
import javax.persistence.JoinColumn;
import javax.persistence.FetchType;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

@Entity
@Getter
@Setter
@Table(name = "users")
public class User extends BaseEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Size(max = 40)
    private String name;

    @NotBlank
    @Size(max = 15)
    @Column(unique = true)
    @NaturalId(mutable=true)
    private String username;

    @NotBlank
    @Size(max = 40)
    @Email
    @Column(unique = true)
    @NaturalId(mutable=true)
    private String email;

    @NotBlank
    @Size(max = 100)
    private String password;

    /*
    @NotNull
    @Column(nullable = false, columnDefinition = "tinyint(1)", length = 1)
    private boolean status;

    @NotNull
    @Column(nullable = false, columnDefinition = "tinyint(1)", length = 1)
    private boolean dormant;

     */

    private LocalDateTime passwordUpdateAt;
    private LocalDateTime lastLoginAt;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();

    public User() {

    }

    public User(String name, String username, String email, String password, LocalDateTime passwordUpdateAt, LocalDateTime lastLoginAt) {
        this.name = name;
        this.username = username;
        this.email = email;
        this.password = password;
        this.passwordUpdateAt = passwordUpdateAt;
        this.lastLoginAt = lastLoginAt;
    }

}