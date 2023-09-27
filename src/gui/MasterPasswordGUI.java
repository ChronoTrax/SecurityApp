package gui;

import tools.EncryptionTools;

import javax.swing.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
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
            try (FileChannel channel = FileChannel.open(Paths.get(MainGUI.masterPasswordFilePath), StandardOpenOption.READ)) {
                // check if file exists
//                if (!file.exists()) {
//                    JOptionPane.showMessageDialog(mainPanel, "Master password file is missing. Please input a new master password.",
//                            "Master Password Missing", JOptionPane.INFORMATION_MESSAGE);
//
//                    new NewMasterPasswordGUI();
//                    dispose();
//                    return;
//                }

                ByteBuffer buffer = ByteBuffer.allocate((int) channel.size());
                channel.read(buffer);

                // Convert the ByteBuffer to a byte array
                byte[] readHash = buffer.array();

                // master password has not been set up
//                if (readHash.length == 0) {
//                    JOptionPane.showMessageDialog(mainPanel, "Master password is missing. Please input a new master password.",
//                            "Master Password Missing", JOptionPane.INFORMATION_MESSAGE);
//
//                    new NewMasterPasswordGUI();
//                    dispose();
//                    return;
//                }

                // compare hash
                char[] passwordInput = submitPasswordField.getPassword();

                byte[] newHash = EncryptionTools.hashPassword(passwordInput);

                if (Arrays.equals(newHash, readHash)) {
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
