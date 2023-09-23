package tools;

import java.util.Arrays;

public class PasswordTest {
    public static String isPasswordStrong(String password) {
        // check length
        if (password.length() < 8) {
            return "WEAK PASSWORD: Password should be at least 8 characters long.";
        }

        // check for upper and lower case
        if (password.toLowerCase().equals(password) || password.toUpperCase().equals(password)) {
            return "WEAK PASSWORD: Password should contain upper and lower case characters.";
        }

        // check for numbers
        {
            boolean pass = false;
            for (Character c : Arrays.asList('1', '2', '3', '4', '5', '6', '7', '8', '9', '0')) {
                if (password.contains(String.valueOf(c))) {
                    pass = true;
                    break;
                }
            }
            if (!pass) {
                return "WEAK PASSWORD: Password should contain a number.";
            }
        }

        return "STRONG PASSWORD.";
    }
}
