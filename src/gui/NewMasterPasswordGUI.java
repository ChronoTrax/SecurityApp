package gui;

import javax.swing.*;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.Arrays;

public class NewMasterPasswordGUI extends JFrame {
    private JPanel mainPanel;
    private JPasswordField newPasswordField;
    private JPasswordField confirmPasswordField;
    private JButton cancelBtn;
    private JButton submitPasswordBtn;

    public NewMasterPasswordGUI() {
        // setup panel
        setContentPane(mainPanel);
        setTitle("Enter Master Password");
        setSize(400, 200);
        setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);

        // reveal window
        setVisible(true);

        submitPasswordBtn.addActionListener(e -> {
            if (Arrays.equals(newPasswordField.getPassword(), confirmPasswordField.getPassword())) {
                char[] newPass = newPasswordField.getPassword();

                MainGUI.masterPassword = newPass;

                // write to file
                try {
                    File file = new File("masterpass.txt");

                    FileWriter fileWriter = new FileWriter(file);
                    BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);

                    bufferedWriter.write(newPass);

                    bufferedWriter.close();
                } catch (Exception exc) {
                    JOptionPane.showMessageDialog(mainPanel, "Something went wrong: " +
                                    exc.getClass() + "\n" + exc.getMessage(),
                            "Error!", JOptionPane.ERROR_MESSAGE);
                }

                // close panel
                dispose();
            } else {
                // confirm password does not match
                JOptionPane.showMessageDialog(mainPanel, "Confirmation password does not match.",
                        "Error!", JOptionPane.ERROR_MESSAGE);
            }
        });

        cancelBtn.addActionListener(e -> dispose());
    }
}
