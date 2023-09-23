package gui;

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

                char[] line = bufferedReader.readLine().toCharArray();

                // master password has not been set up
                if (line.length == 0) {
                    JOptionPane.showMessageDialog(mainPanel, "Master password is missing. Please input a new master password.",
                            "Master Password Missing", JOptionPane.INFORMATION_MESSAGE);

                    new NewMasterPasswordGUI();
                    dispose();
                    return;
                }

                bufferedReader.close();

                if (Arrays.equals(line, submitPasswordField.getPassword())) {
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
