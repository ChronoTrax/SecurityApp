package gui;

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
    private JButton generatePasswordBtn;
    private JTextArea generatePasswordField;

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

            String result = tools.PasswordTools.isPasswordStrong(password);

            passwordTestResultField.setText(result);
        });
    }

    public static void main(String[] args) {
        new MainGUI();
    }
}
