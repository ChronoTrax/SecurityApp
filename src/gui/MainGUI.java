package gui;

import tools.DatabaseTools;
import tools.EncryptionTools;
import tools.PasswordTools;

import javax.swing.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class MainGUI extends JFrame {
    public static final String masterPasswordFilePath = "masterpass.txt";

    public static char[] masterPassword = null;
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
    private JPasswordField savePasswordField;
    private JButton savePasswordBtn;
    private JTextArea hashResultField;
    private JButton hashFileBtn;
    private JTextField loadWebsiteSearchField;
    private JButton loadWebsiteSearchBtn;
    private JTextField loadUsernameSearchField;
    private JButton loadUsernameSearchBtn;
    private JTextArea loadPasswordResultField;
    private JButton deleteLoadedPasswordBtn;
    private JButton deleteDatabaseBtn;
    private DatabaseTools.PasswordRecord loadedPasswordRecord = null;


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

        // test password
        submitPasswordTestBtn.addActionListener(e -> testPassword());
        passwordTestInputField.addActionListener(e -> testPassword());

        // generate password
        genPasswordBtn.addActionListener(e -> generatePassword());

        // save password
        savePasswordBtn.addActionListener(e -> savePassword());
        saveWebsiteField.addActionListener(e -> savePassword());
        saveUsernameField.addActionListener(e -> savePassword());
        savePasswordField.addActionListener(e -> savePassword());

        // load password with website search
        loadWebsiteSearchBtn.addActionListener(e -> searchWebsite());
        loadWebsiteSearchField.addActionListener(e -> searchWebsite());

        // load password with username search
        loadUsernameSearchBtn.addActionListener(e -> searchUsername());
        loadUsernameSearchField.addActionListener(e -> searchUsername());

        // delete loaded password
        deleteLoadedPasswordBtn.addActionListener(e -> deletePassword());

        // delete database
        deleteDatabaseBtn.addActionListener(e -> deleteDatabase());

        // upload file for hashing
        hashFileBtn.addActionListener(e -> hashFile());
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

    private void hashFile() {
        // let user select file
        JFileChooser fileChooser = new JFileChooser();
        int returnValue = fileChooser.showOpenDialog(null);

        if (returnValue == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileChooser.getSelectedFile();

            try {
                // MD5 hash
                String md5 = EncryptionTools.calculateMD5(selectedFile.getAbsolutePath());
                hashResultField.setText("MD5 Hash: " + md5 + "\n");

                // sha256 hash
                String sha256 = EncryptionTools.calculateSHA256(selectedFile.getAbsolutePath());
                hashResultField.append("SHA-256 Hash: " + sha256);
            } catch (IOException | NoSuchAlgorithmException exc) {
                JOptionPane.showMessageDialog(mainPanel, "Something went wrong: " +
                                exc.getClass() + "\n" + exc.getMessage(),
                        "Error!", JOptionPane.ERROR_MESSAGE);
            }

        } else {
            System.out.println("No file selected. ");
        }
    }

    private void deleteDatabase() {
        int choice = JOptionPane.showConfirmDialog(mainPanel,
                "Are you sure you want to delete all saved passwords?",
                "Confirmation", JOptionPane.YES_NO_OPTION);

        if (choice == JOptionPane.YES_OPTION) {
            try {
                if (DatabaseTools.deletePasswordDatabase()) {
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
    }

    private void deletePassword() {
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
                if (DatabaseTools.deletePasswordRecord(loadedPasswordRecord.website())) {
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
    }

    private void savePassword() {
        try {
            // check for master password
            if (masterPassword == null) {
                promptMasterPassword();
                return;
            }

            // get user inputs
            String website = saveWebsiteField.getText();
            String username = saveUsernameField.getText();
            char[] password = savePasswordField.getPassword();

            // try saving password to database
            if (DatabaseTools.savePassword(website, username, password)) {
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
    }

    private void searchUsername() {
        String username = loadUsernameSearchField.getText();

        try {
            DatabaseTools.PasswordRecord record = DatabaseTools.findPasswordRecordWithUsername(username);
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
            DatabaseTools.PasswordRecord record = DatabaseTools.findPasswordRecordWithWebsite(website);
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
}
