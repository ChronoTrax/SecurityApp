package tools;

import java.util.Random;

public class PasswordTools {
    private static final String lowercase = "abcdefghijklmnopqrstuvwxyz";
    private static final String uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String numbers = "0123456789";
    private static final String specials = "`~!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?";

    /**
     * Tests if a password meets the length and complexity requirements of a strong password.
     * A strong password should be at least 8 characters long, and contain at least one uppercase letter, lowercase
     * letter, a number, and a special character.
     *
     * @param password the password to be tested.
     * @return a String explaining the password's strength.
     */
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

    /**
     * Generates a random password of length 8 - 16, with random letters, numbers, and special characters.
     *
     * @return a randomized password String.
     */
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
