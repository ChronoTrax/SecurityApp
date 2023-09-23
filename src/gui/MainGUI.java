package gui;

import tools.*;

import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.IOException;

public class MainGUI extends JFrame{
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

    private JButton uploadFileBtn;

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

        // upload file button
        uploadFileBtn.addActionListener(e -> {
            try {
               Desktop.getDesktop().open(new File(System.getProperty("user.home")));
            } catch (IOException ex) {
                throw new RuntimeException(ex);
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
