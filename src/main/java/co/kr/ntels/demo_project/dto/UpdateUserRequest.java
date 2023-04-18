package co.kr.ntels.demo_project.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;

@Getter
@Setter
@NoArgsConstructor
public class UpdateUserRequest {

    @NotNull
    private Long id;
    private String name;
    private String username;
    @Email
    private String email;
    private String currentPassword;
    private String newPassword;
}
