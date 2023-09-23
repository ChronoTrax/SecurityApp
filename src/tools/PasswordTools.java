package tools;

import java.util.Random;

public class PasswordTools {
    private static final String lowercase = "abcdefghijklmnopqrstuvwxyz";
    private static final String uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String numbers = "0123456789";
    private static final String specials = "`~!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?";

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
            for (Character c : numbers.toCharArray()) {
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
            for (Character c : specials.toCharArray()) {
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

    public static String generatePassword() {
        Random rand = new Random();

        String allChars = lowercase + uppercase + numbers + specials;

        int length = rand.nextInt(9) + 8;

        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < length; i++) {
            sb.append(allChars.charAt(rand.nextInt(allChars.length())));
        }

        return sb.toString();
    }
}
