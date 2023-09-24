package gui;

import tools.HashTools;
import tools.PasswordTools;
import tools.SavingTools;

import javax.swing.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
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
    private JButton loadWebsiteSearchBtn;
    private JTextField loadUsernameSearchField;
    private JButton loadUsernameSearchBtn;
    private JTextArea loadPasswordResultField;
    private JButton deleteLoadedPasswordBtn;
    private JButton deleteDatabaseBtn;


    private SavingTools.PasswordRecord loadedPasswordRecord = null;


    public static char[] masterPassword = null;


    public MainGUI() {
        // setup panel
        setContentPane(mainPanel);
        setTitle("Security App");
        setSize(1200, 675);
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);

        // reveal window
        setVisible(true);

        // ask for master password
        promptMasterPassword();

        // test password button
        submitPasswordTestBtn.addActionListener(e -> testPassword());

        // generate password button
        genPasswordBtn.addActionListener(e -> generatePassword());

        // save password button
        savePasswordBtn.addActionListener(e -> {
            try {
                // check for master password
                if (masterPassword == null) {
                    promptMasterPassword();
                    return;
                }

                // get user inputs
                String website = saveWebsiteField.getText();
                String username = saveUsernameField.getText();
                String password = savePasswordField.getText();

                // try saving password to database
                if (SavingTools.savePassword(masterPassword, website, username, password)) {
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
        loadWebsiteSearchBtn.addActionListener(e -> searchWebsite());

        // load password with username search
        loadUsernameSearchBtn.addActionListener(e -> searchUsername());

        // delete loaded password
        deleteLoadedPasswordBtn.addActionListener(e -> {
            if (loadedPasswordRecord == null) {
                JOptionPane.showMessageDialog(mainPanel, "No password has been loaded yet.",
                        "Error!", JOptionPane.ERROR_MESSAGE);

                return;
            }

            int choice = JOptionPane.showConfirmDialog(mainPanel,
                    "Are you sure you want to delete password for: " + loadedPasswordRecord.website() + "?",
                    "Confirmation", JOptionPane.YES_NO_OPTION);

            if (choice == JOptionPane.YES_OPTION) {
                try {
                    if (SavingTools.deletePasswordRecord(loadedPasswordRecord.website())) {
                        JOptionPane.showMessageDialog(mainPanel, "Deleted password.",
                                "Saved", JOptionPane.INFORMATION_MESSAGE);

                        // clear password field
                        loadPasswordResultField.setText("");

                        // reset loaded password
                        loadedPasswordRecord = null;
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
                        loadedPasswordRecord = null;
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
                    //hashField.setLineWrap(true);

                    String md5 = HashTools.getMD5(selectedFile.getAbsolutePath());
                    hashField.setText("MD5 Hash: " + md5 + "\n");

                    String sha256 = HashTools.calculateSHA256(selectedFile.getAbsolutePath());
                    hashField.append("SHA-256 Hash: " + sha256);
                } catch (IOException | NoSuchAlgorithmException exc) {
                    JOptionPane.showMessageDialog(mainPanel, "Something went wrong: " +
                                    exc.getClass() + "\n" + exc.getMessage(),
                            "Error!", JOptionPane.ERROR_MESSAGE);
                }

            } else {
                System.out.println("No file selected. ");
            }

        });

        passwordTestInputField.addActionListener(e -> testPassword());

        loadWebsiteSearchField.addActionListener(e -> searchWebsite());

        loadUsernameSearchField.addActionListener(e -> searchUsername());
    }

    private void searchUsername() {
        String username = loadUsernameSearchField.getText();

        try {
            SavingTools.PasswordRecord record = SavingTools.findPasswordRecordWithUsername(username);
            if (record == null) {
                JOptionPane.showMessageDialog(mainPanel, "Could not find password for: " + username,
                        "Could Not find Password", JOptionPane.ERROR_MESSAGE);
                return;
            }

            loadPasswordResultField.setText(record.toString());
            loadedPasswordRecord = record;

            // clear input fields
            loadUsernameSearchField.setText("");
        } catch (Exception exc) {
            JOptionPane.showMessageDialog(mainPanel, "Something went wrong: " +
                            exc.getClass() + "\n" + exc.getMessage(),
                    "Error!", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void searchWebsite() {
        String website = loadWebsiteSearchField.getText();

        try {
            SavingTools.PasswordRecord record = SavingTools.findPasswordRecordWithWebsite(website);
            if (record == null) {
                JOptionPane.showMessageDialog(mainPanel, "Could not find password for: " + website,
                        "Could Not find Password", JOptionPane.ERROR_MESSAGE);
                return;
            }

            loadPasswordResultField.setText(record.toString());
            loadedPasswordRecord = record;

            // clear input fields
            loadWebsiteSearchField.setText("");
        } catch (Exception exc) {
            JOptionPane.showMessageDialog(mainPanel, "Something went wrong: " +
                            exc.getClass() + "\n" + exc.getMessage(),
                    "Error!", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void generatePassword() {
        String newPassword = PasswordTools.generatePassword();

        genPasswordField.setText(newPassword);
    }

    private void testPassword() {
        String password = passwordTestInputField.getText();

        String result = PasswordTools.isPasswordStrong(password);

        passwordTestResultField.setText(result);
    }

    private void promptMasterPassword() {
        try {
            // check if master password has been set up yet
            File file = new File("masterpass.txt");

            // check if file exists
            if (!file.exists()) {
                JOptionPane.showMessageDialog(mainPanel, "Master password has not been set up yet.",
                        "Master Password not Entered", JOptionPane.INFORMATION_MESSAGE);

                new NewMasterPasswordGUI();
                return;
            }

            FileReader fileReader = new FileReader(file);
            BufferedReader bufferedReader = new BufferedReader(fileReader);

            String line = bufferedReader.readLine();

            // master password has not been set up
            if (line == null) {
                JOptionPane.showMessageDialog(mainPanel, "Master password has not been set up yet.",
                        "Master Password not Entered", JOptionPane.INFORMATION_MESSAGE);

                new NewMasterPasswordGUI();
                return;
            }

            bufferedReader.close();

            // prompt for master password
            JOptionPane.showMessageDialog(mainPanel, "Master password has not been entered yet.",
                    "Master Password not Entered", JOptionPane.INFORMATION_MESSAGE);
            new MasterPasswordGUI();
        } catch (Exception exc) {
            JOptionPane.showMessageDialog(mainPanel, "Something went wrong: " +
                            exc.getClass() + "\n" + exc.getMessage(),
                    "Error!", JOptionPane.ERROR_MESSAGE);
        }
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
