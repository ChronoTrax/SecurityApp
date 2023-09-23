package tools;

import java.util.Arrays;

public class PasswordTest {
    private static char[] lowercase = "abcdefghijklmnopqrstuvwxyz".toCharArray();
    private static char[] uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
    private static char[] numbers = "0123456789".toCharArray();
    private static char[] specials = "`~!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?".toCharArray();

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
            for (Character c : numbers) {
                if (password.contains(String.valueOf(c))) {
                    pass = true;
                    break;
                }
            }
            if (!pass) {
                return "WEAK PASSWORD: Password should contain a number.";
            }
        }

        // check for special characters
        {
            boolean pass = false;
            for (Character c : specials) {
                if (password.contains(String.valueOf(c))) {
                    pass = true;
                    break;
                }
            }
            if (!pass) {
                return "WEAK PASSWORD: Password should contain a special character.";
            }
        }

        return "STRONG PASSWORD.";
    }
}
