package co.kr.ntels.demo_project.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

@Getter
@Setter
@NoArgsConstructor
public class CheckEmailRequest {
    @NotBlank
    @Size(max = 40)
    @Email
    private String email;

}
