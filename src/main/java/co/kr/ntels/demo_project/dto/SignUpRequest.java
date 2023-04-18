package co.kr.ntels.demo_project.dto;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import javax.validation.constraints.Email;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class SignUpRequest {
    @NotBlank
    @Size(min = 3, max = 40)
    private String name;
    @NotBlank
    @Size(min = 3, max = 15)
    private String username;
    @NotBlank
    @Size(max = 40)
    @Email
    private String email;
    @NotBlank
    @Size(min = 8, max = 30)
    private String password;
}

