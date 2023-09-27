package gui;

import tools.EncryptionTools;

import javax.swing.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
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
                char[] inputPassword = newPasswordField.getPassword();

                // validate password
                if (inputPassword.length == 0) {
                    JOptionPane.showMessageDialog(mainPanel, "Password cannot be blank.","Error!",
                            JOptionPane.ERROR_MESSAGE);
                    return;
                }

                MainGUI.masterPassword = inputPassword;

                // write to file
                try (FileChannel channel = FileChannel.open(Paths.get(MainGUI.masterPasswordFilePath),
                        StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
                    // hash password for saving
                    byte[] hash = EncryptionTools.hashPassword(inputPassword);

                    int bytesWritten = channel.write(ByteBuffer.wrap(hash));
                } catch (Exception exc) {
                    JOptionPane.showMessageDialog(mainPanel, "Something went wrong: " +
                                    exc.getClass() + "\n" + exc.getMessage(), "Error!", JOptionPane.ERROR_MESSAGE);
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
