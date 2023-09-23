package gui;

import tools.*;

import javax.swing.*;

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

        });
    }

    public static void main(String[] args) {
        new MainGUI();
    }
}
