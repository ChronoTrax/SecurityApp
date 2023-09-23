package tools;

public class PasswordTest {
    public static String isPasswordStrong(String password) {
        if (password.length() < 8) {
            return "WEAK PASSWORD: password should be at least 8 characters long.";
        }

        if (password.toLowerCase().equals(password) || password.toUpperCase().equals(password)) {
            return "WEAK PASSWORD: password should contain upper and lower case characters.";
        }

        return "STRONG PASSWORD.";
    }
}
