package tools;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.sql.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;

public class SavingTools {
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
        byte[] salt = HashTools.generateSalt();

        // encrypt password
        String encryptedPass = EncryptionTools.encryptPassword(password, salt);

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
        ArrayList<PasswordRecord> list = getPasswordRecords();

        for (PasswordRecord record :
                list) {
            if (website.equals(record.website)) {
                return record;
            }
        }

        return null;
    }

    public static PasswordRecord findPasswordRecordWithUsername(String username) throws Exception {
        // get list
        ArrayList<PasswordRecord> list = getPasswordRecords();

        for (PasswordRecord record :
                list) {
            if (username.equals(record.username)) {
                return record;
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

    private static ArrayList<PasswordRecord> getPasswordRecords() throws Exception {
        PreparedStatement ps = CONNECTION.prepareStatement(SELECT_PASSWORD_RECORDS);
        ps.execute();
        ResultSet rs = ps.getResultSet();

        // create list
        ArrayList<PasswordRecord> list = new ArrayList<>();

        // loop through select results
        while (rs.next()) {
            // decrypt password
            String pass = EncryptionTools.decryptPassword(rs.getString("encryptedPass").toCharArray(), rs.getString("salt").getBytes());

            // create new Record
            PasswordRecord record = new PasswordRecord(rs.getString("website"),
                    rs.getString("username"), pass);

            list.add(record);
        }

        return list;
    }

    private static void createTables() throws SQLException {
        // create tables
        PreparedStatement ps = CONNECTION.prepareStatement(CREATE_DATABASE);
        ps.execute();
    }

    // TODO: Remove
/*    public static void getHashAndSalt() {
        String password = "";
        byte[] salt = generateSalt();

        try {
            int iterations = 10000; // number of iterations
            int keyLength = 256; // key length in bits

            byte[] hashedPassword = hashPassword(password.toCharArray(), salt, iterations, keyLength);
            String hashedPasswordBase64 = Base64.getEncoder().encodeToString(hashedPassword);

            System.out.println("Salt: " + Base64.getEncoder().encodeToString(salt));
            System.out.println("Hashed Password: " + hashedPasswordBase64);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }*/

    public record PasswordRecord(String website, String username, String encryptedPass) {
        @Override
        public String toString() {
            return "Website: " + website + '\n' +
                    "Username: " + username + '\n' +
                    "Hashed Password: " + encryptedPass;
        }
    }
}
