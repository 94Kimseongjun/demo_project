package co.kr.ntels.demo_project.dto;

import co.kr.ntels.demo_project.security.dto.Token;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter @Setter
@AllArgsConstructor
public class LoginResponse {
    private boolean passwordUpdateRequired;

}
