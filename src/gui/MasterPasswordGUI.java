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

                byte[] hash = new byte[32];
                byte[] readHash = bufferedReader.readLine().getBytes();

                // master password has not been set up
                if (readHash.length == 0) {
                    JOptionPane.showMessageDialog(mainPanel, "Master password is missing. Please input a new master password.",
                            "Master Password Missing", JOptionPane.INFORMATION_MESSAGE);

                    new NewMasterPasswordGUI();
                    dispose();
                    return;
                }

                for (int i = 0; i < 32; i++) {
                    byte b = readHash[i];
                    if (b != ',' && b != '[' && b != ']') {
                        // Convert the byte to a character and process it
                        hash[i] = b;
                    }
                }

                byte[] salt = new byte[16];
                byte[] readSalt = bufferedReader.readLine().getBytes();

                for (int i = 0; i < 16; i++) {
                    byte b = readSalt[i];
                    if (b != ',' && b != '[' && b != ']') {
                        // Convert the byte to a character and process it
                        salt[i] = b;
                    }
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
