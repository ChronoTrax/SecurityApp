package gui;

import tools.*;

import javax.swing.*;
import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class MainGUI extends JFrame {
    private JPanel mainPanel;
    private JPanel passwordTestPanel;
    private JPanel hashPanel;
    private JTextField passwordTestField;
    private JButton submitTestPasswordBtn;
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


    public MainGUI() {
        // setup panel
        setContentPane(mainPanel);
        setTitle("Security App");
        setSize(800, 450);
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);

        // reveal window
        setVisible(true);

        // test password button
        submitTestPasswordBtn.addActionListener(e -> {
            String password = passwordTestField.getText();

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
                }
            } catch (Exception exc) {
                JOptionPane.showMessageDialog(mainPanel, "Something went wrong: " +
                                exc.getClass() + "\n" + exc.getMessage(),
                        "Error!", JOptionPane.ERROR_MESSAGE);
            }
        });

        // load password with website search
        loadWebsiteSearchbtn.addActionListener(e -> {

        });

        // load password with username search
        loadUsernameSearchBtn.addActionListener(e -> {

        });

        // upload file button
        uploadFileBtn.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            int returnValue = fileChooser.showOpenDialog(null);

            if (returnValue == JFileChooser.APPROVE_OPTION) {
                File selectedFile = fileChooser.getSelectedFile();

                try {
                    String hash = HashTest.getMD5(selectedFile.getAbsolutePath());
                    hashField.setText("MD5 Hash: " + hash);
                    //System.out.println("MD5 Hash: " + hash);
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
