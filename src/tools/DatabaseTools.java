package tools;

import gui.MainGUI;

import java.sql.*;
import java.util.ArrayList;

public class DatabaseTools {
    private static final String DB_NAME = "jdbc:sqlite:passDB.sqlite";
    private static final Connection CONNECTION;
    private static final String CREATE_DATABASE = "create table if not exists Passwords (website varchar(150) not null primary key, username varchar(50) not null, encryptedPass varchar(300) not null, salt varchar(16));";
    private static final String DROP_DATABASE = "drop table if exists Passwords;";
    private static final String INSERT_PASSWORD_RECORD = "insert into Passwords values (?, ?, ?, ?);";
    private static final String SELECT_PASSWORD_RECORDS = "select * from Passwords;";
    private static final String DELETE_PASSWORD_RECORD = "delete from Passwords where website = ?;";

    // establish connection and statement
    static {
        try {
            CONNECTION = DriverManager.getConnection(DB_NAME);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean savePassword(String website, String username, char[] password) throws Exception {
        // check null or blank
        if (website == null || website.isBlank() ||
                username == null || username.isBlank() ||
                password == null || password.length == 0) {
            throw new RuntimeException("Website, username, and password cannot be blank.");
        }

        // check website length
        if (website.length() > 150) {
            throw new RuntimeException("Website cannot be longer than 150 character.");
        }

        // check username length
        if (username.length() > 50) {
            throw new RuntimeException("Username cannot be longer than 50 character.");
        }

        // generate salt
        byte[] salt = EncryptionTools.generateSalt();

        // encrypt password
        String encryptedPass = EncryptionTools.encryptUserPassword(MainGUI.masterPassword, password, salt);

        // make sure table exists
        createTables();

        // add to database
        PreparedStatement ps = CONNECTION.prepareStatement(INSERT_PASSWORD_RECORD);
        ps.setString(1, website);
        ps.setString(2, username);
        ps.setString(3, encryptedPass);
        ps.setBytes(4, salt);
        ps.execute();

        return true;
    }

    public static PasswordRecord findPasswordRecordWithWebsite(String website) throws Exception {
        // get list
        ArrayList<EncryptedPasswordRecord> list = getPasswordRecords();

        for (EncryptedPasswordRecord record :
                list) {
            if (website.equals(record.website)) {
                char[] pass = EncryptionTools.decryptUserPassword(MainGUI.masterPassword, record.password, record.salt);

                return new PasswordRecord(record.website, record.username, new String(pass));
            }
        }

        return null;
    }

    public static PasswordRecord findPasswordRecordWithUsername(String username) throws Exception {
        // get list
        ArrayList<EncryptedPasswordRecord> list = getPasswordRecords();

        for (EncryptedPasswordRecord record :
                list) {
            if (username.equals(record.username)) {
                char[] pass = EncryptionTools.decryptUserPassword(MainGUI.masterPassword, record.password, record.salt);

                return new PasswordRecord(record.website, record.username, new String(pass));
            }
        }

        return null;
    }

    public static boolean deletePasswordRecord(String website) throws SQLException {
        if (website == null || website.isBlank()) {
            throw new RuntimeException("website cannot be blank");
        }

        PreparedStatement ps = CONNECTION.prepareStatement(DELETE_PASSWORD_RECORD);
        ps.setString(1, website);
        ps.execute();

        return true;
    }

    public static boolean deletePasswordDatabase() throws SQLException {
        PreparedStatement ps = CONNECTION.prepareStatement(DROP_DATABASE);
        ps.execute();

        return true;
    }

    private static ArrayList<EncryptedPasswordRecord> getPasswordRecords() throws Exception {
        PreparedStatement ps = CONNECTION.prepareStatement(SELECT_PASSWORD_RECORDS);
        ps.execute();
        ResultSet rs = ps.getResultSet();

        // create list
        ArrayList<EncryptedPasswordRecord> list = new ArrayList<>();

        // loop through select results
        while (rs.next()) {
            // create new Record
            EncryptedPasswordRecord record = new EncryptedPasswordRecord(rs.getString("website"),
                    rs.getString("username"),
                    rs.getString("encryptedPass"),
                    rs.getBytes("salt"));

            list.add(record);
        }

        return list;
    }

    private static void createTables() throws SQLException {
        // create tables
        PreparedStatement ps = CONNECTION.prepareStatement(CREATE_DATABASE);
        ps.execute();
    }

    public record PasswordRecord(String website, String username, String encryptedPass) {
        @Override
        public String toString() {
            return "Website: " + website + '\n' +
                    "Username: " + username + '\n' +
                    "Hashed Password: " + encryptedPass;
        }
    }

    public record EncryptedPasswordRecord(String website, String username, String password, byte[] salt) {

    }
}
