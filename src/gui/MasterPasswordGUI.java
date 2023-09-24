package gui;

import tools.HashTools;

import javax.swing.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.Arrays;

public class MasterPasswordGUI extends JFrame {
    private JPanel mainPanel;
    private JPasswordField submitPasswordField;
    private JButton submitPasswordBtn;
    private JButton cancelBtn;

    public MasterPasswordGUI() {
        // setup panel
        setContentPane(mainPanel);
        setTitle("Enter Master Password");
        setSize(400, 200);
        setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);

        // reveal window
        setVisible(true);

        submitPasswordBtn.addActionListener(e -> {
            try {
                // check if master password has been set up yet
                File file = new File("masterpass.txt");

                // check if file exists
                if (!file.exists()) {
                    JOptionPane.showMessageDialog(mainPanel, "Master password file is missing. Please input a new master password.",
                            "Master Password Missing", JOptionPane.INFORMATION_MESSAGE);

                    new NewMasterPasswordGUI();
                    dispose();
                    return;
                }

                FileReader fileReader = new FileReader(file);
                BufferedReader bufferedReader = new BufferedReader(fileReader);

                String inputLine = bufferedReader.readLine();

                // Remove square brackets and spaces
                String cleanString = inputLine.replaceAll("[\\[\\] ]", "");

                // Split the string into individual decimal values
                String[] decimalValues = cleanString.split(",");

                // Create a byte array and populate it with parsed values
                byte[] hash = new byte[decimalValues.length];
                for (int i = 0; i < decimalValues.length; i++) {
                    hash[i] = (byte) Integer.parseInt(decimalValues[i].trim());
                }

                // Display the byte array
                for (byte b : hash) {
                    System.out.print(b + " ");
                }

//                // master password has not been set up
//                if (readHash.length == 0) {
//                    JOptionPane.showMessageDialog(mainPanel, "Master password is missing. Please input a new master password.",
//                            "Master Password Missing", JOptionPane.INFORMATION_MESSAGE);
//
//                    new NewMasterPasswordGUI();
//                    dispose();
//                    return;
//                }

                inputLine = bufferedReader.readLine();

                // Remove square brackets and spaces
                cleanString = inputLine.replaceAll("[\\[\\] ]", "");

                // Split the string into individual decimal values
                decimalValues = cleanString.split(",");

                // Create a byte array and populate it with parsed values
                byte[] salt = new byte[decimalValues.length];
                for (int i = 0; i < decimalValues.length; i++) {
                    salt[i] = (byte) Integer.parseInt(decimalValues[i].trim());
                }

                // Display the byte array
                for (byte b : salt) {
                    System.out.print(b + " ");
                }

                bufferedReader.close();

                // compare hash
                char[] passwordInput = submitPasswordField.getPassword();

                byte[] newHash = HashTools.hashPassword(passwordInput, salt);

                if (Arrays.equals(newHash, hash)) {
                    // correct password
                    MainGUI.masterPassword = submitPasswordField.getPassword();

                    // close panel
                    dispose();
                } else {
                    // password does not match
                    JOptionPane.showMessageDialog(mainPanel, "Password does not match master password.",
                            "Password Does Not Match", JOptionPane.ERROR_MESSAGE);
                }
            } catch (Exception exc) {
                JOptionPane.showMessageDialog(mainPanel, "Something went wrong: " +
                                exc.getClass() + "\n" + exc.getMessage(),
                        "Error!", JOptionPane.ERROR_MESSAGE);
            }
        });

        cancelBtn.addActionListener(e -> dispose());
    }
}
