package co.kr.ntels.demo_project.util;

import org.springframework.stereotype.Component;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class PasswordValidator {
    private static final String PASSWORD_PATTERN = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[$@$!%*?&])[A-Za-z\\d$@$!%*?&]{8,30}$";
    private static final String REPEATED_CHARACTERS_PATTERN = "(.)\\1{2,}";
    private static final String KEYBOARD_PATTERNS[] = {"1234", "4321", "qwert", "trewq", "asdfg", "gfdsa", "zxcvb", "bvxcz"};

    private Pattern pattern;
    private Matcher matcher;

    public boolean validate(final String password, final String username) {
        // Check if password matches the password pattern
        pattern = Pattern.compile(PASSWORD_PATTERN);
        matcher = pattern.matcher(password);
        if (!matcher.matches()) {
            return false;
        }

        // Check if password contains repeated characters
        pattern = Pattern.compile(REPEATED_CHARACTERS_PATTERN);
        matcher = pattern.matcher(password);
        if (matcher.find()) {
            return false;
        }

        // Check if password contains keyboard patterns
        for (String keyboardPattern : KEYBOARD_PATTERNS) {
            if (password.toLowerCase().contains(keyboardPattern)) {
                return false;
            }
        }

        // Check if password contains user ID
        if (password.toLowerCase().contains(username.toLowerCase())) {
            return false;
        }

        return true;
    }
}
