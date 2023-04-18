package co.kr.ntels.demo_project.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;

@Getter
@Setter
@NoArgsConstructor
public class CheckUsernameRequest {
    @NotBlank
    @Size(min = 3, max = 15)
    private String username;
}
