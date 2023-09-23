package gui;

import tools.HashTools;
import tools.PasswordTools;
import tools.SavingTools;

import javax.swing.*;
import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class MainGUI extends JFrame {
    private JPanel mainPanel;
    private JPanel passwordTestPanel;
    private JPanel hashPanel;
    private JTextField passwordTestInputField;
    private JButton submitPasswordTestBtn;
    private JTextArea passwordTestResultField;
    private JPanel genPasswordPanel;
    private JPanel savePasswordPanel;
    private JPanel loadPasswordPanel;
    private JButton genPasswordBtn;
    private JTextArea genPasswordField;
    private JTextField saveWebsiteField;
    private JTextField saveUsernameField;
    private JTextField savePasswordField;
    private JButton savePasswordBtn;
    private JTextArea hashField;
    private JButton uploadFileBtn;
    private JTextField loadWebsiteSearchField;
    private JButton loadWebsiteSearchbtn;
    private JTextField loadUsernameSearchField;
    private JButton loadUsernameSearchBtn;
    private JTextArea loadPasswordResultField;
    private JButton deleteLoadedPasswordBtn;
    private JButton deleteDatabaseBtn;

    private SavingTools.PasswordRecord loadedPassword = null;


    public MainGUI() {
        // setup panel
        setContentPane(mainPanel);
        setTitle("Security App");
        setSize(800, 450);
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);

        // reveal window
        setVisible(true);

        // test password button
        submitPasswordTestBtn.addActionListener(e -> {
            String password = passwordTestInputField.getText();

            String result = PasswordTools.isPasswordStrong(password);

            passwordTestResultField.setText(result);
        });

        // generate password button
        genPasswordBtn.addActionListener(e -> {
            String newPassword = PasswordTools.generatePassword();

            genPasswordField.setText(newPassword);
        });

        // save password button
        savePasswordBtn.addActionListener(e -> {
            String website = saveWebsiteField.getText();
            String username = saveUsernameField.getText();
            String password = savePasswordField.getText();

            try {
                if (SavingTools.savePassword(new SavingTools.PasswordRecord(website, username, password))) {
                    JOptionPane.showMessageDialog(mainPanel, "Saved password.",
                            "Saved", JOptionPane.INFORMATION_MESSAGE);

                    // clear input fields
                    saveWebsiteField.setText("");
                    saveUsernameField.setText("");
                    savePasswordField.setText("");
                }
            } catch (Exception exc) {
                JOptionPane.showMessageDialog(mainPanel, "Something went wrong: " +
                                exc.getClass() + "\n" + exc.getMessage(),
                        "Error!", JOptionPane.ERROR_MESSAGE);
            }
        });

        // load password with website search
        loadWebsiteSearchbtn.addActionListener(e -> {
            String website = loadWebsiteSearchField.getText();

            try {
                SavingTools.PasswordRecord record = SavingTools.findPasswordRecordWithWebsite(website);
                if (record == null) {
                    JOptionPane.showMessageDialog(mainPanel, "Could not find password for: " + website,
                            "Could Not find Password", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                loadPasswordResultField.setText(record.toString());
                loadedPassword = record;

                // clear input fields
                loadWebsiteSearchField.setText("");
            } catch (Exception exc) {
                JOptionPane.showMessageDialog(mainPanel, "Something went wrong: " +
                                exc.getClass() + "\n" + exc.getMessage(),
                        "Error!", JOptionPane.ERROR_MESSAGE);
            }
        });

        // load password with username search
        loadUsernameSearchBtn.addActionListener(e -> {
            String username = loadUsernameSearchField.getText();

            try {
                SavingTools.PasswordRecord record = SavingTools.findPasswordRecordWithUsername(username);
                if (record == null) {
                    JOptionPane.showMessageDialog(mainPanel, "Could not find password for: " + username,
                            "Could Not find Password", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                loadPasswordResultField.setText(record.toString());
                loadedPassword = record;

                // clear input fields
                loadUsernameSearchField.setText("");
            } catch (Exception exc) {
                JOptionPane.showMessageDialog(mainPanel, "Something went wrong: " +
                                exc.getClass() + "\n" + exc.getMessage(),
                        "Error!", JOptionPane.ERROR_MESSAGE);
            }
        });

        // delete loaded password
        deleteLoadedPasswordBtn.addActionListener(e -> {
            if (loadedPassword == null) {
                JOptionPane.showMessageDialog(mainPanel, "No password has been loaded yet.",
                        "Error!", JOptionPane.ERROR_MESSAGE);

                return;
            }

            int choice = JOptionPane.showConfirmDialog(mainPanel,
                    "Are you sure you want to delete password for: " + loadedPassword.website() + "?",
                    "Confirmation", JOptionPane.YES_NO_OPTION);

            if (choice == JOptionPane.YES_OPTION) {
                try {
                    if (SavingTools.deletePasswordRecord(loadedPassword.website())) {
                        JOptionPane.showMessageDialog(mainPanel, "Deleted password.",
                                "Saved", JOptionPane.INFORMATION_MESSAGE);

                        // clear password field
                        loadPasswordResultField.setText("");

                        // reset loaded password
                        loadedPassword = null;
                    }
                } catch (Exception exc) {
                    JOptionPane.showMessageDialog(mainPanel, "Something went wrong: " +
                                    exc.getClass() + "\n" + exc.getMessage(),
                            "Error!", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        deleteDatabaseBtn.addActionListener(e -> {
            int choice = JOptionPane.showConfirmDialog(mainPanel,
                    "Are you sure you want to delete all saved passwords?",
                    "Confirmation", JOptionPane.YES_NO_OPTION);

            if (choice == JOptionPane.YES_OPTION) {
                try {
                    if (SavingTools.deletePasswordDatabase()) {
                        JOptionPane.showMessageDialog(mainPanel, "Deleted saved passwords.",
                                "Saved", JOptionPane.INFORMATION_MESSAGE);

                        // clear password field
                        loadPasswordResultField.setText("");

                        // reset loaded password
                        loadedPassword = null;
                    }
                } catch (Exception exc) {
                    JOptionPane.showMessageDialog(mainPanel, "Something went wrong: " +
                                    exc.getClass() + "\n" + exc.getMessage(),
                            "Error!", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        // upload file button
        uploadFileBtn.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            int returnValue = fileChooser.showOpenDialog(null);

            if (returnValue == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();

                try {
                    String md5 = HashTools.getMD5(selectedFile.getAbsolutePath());
                    hashField.setText("MD5 Hash: " + md5 + "\n");

                    String sha256 = HashTools.calculateSHA256(selectedFile.getAbsolutePath());
                    hashField.append("SHA-256 Hash: " + sha256);
                } catch (IOException | NoSuchAlgorithmException ex) {
                    JOptionPane.showMessageDialog(mainPanel, "Something went wrong: " +
                                    ex.getClass() + "\n" + ex.getMessage(),
                            "Error!", JOptionPane.ERROR_MESSAGE);
                }

            } else {
                System.out.println("No file selected. ");
            }

        });
    }

    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName());
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException |
                 UnsupportedLookAndFeelException e) {
            throw new RuntimeException(e);
        }
        new MainGUI();
    }
}
