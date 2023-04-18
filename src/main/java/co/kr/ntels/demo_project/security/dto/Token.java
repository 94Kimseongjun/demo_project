package co.kr.ntels.demo_project.security.dto;

import lombok.Builder;
import lombok.Data;

import java.util.Date;

@Builder
@Data
public class Token {
    private String accessToken;
    private String refreshToken;
    private Date expiresIn;
    private Date refreshExpiresIn;
}
