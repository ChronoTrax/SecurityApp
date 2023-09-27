package tools;

import gui.MainGUI;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.util.ArrayList;

public class DatabaseTools {
    private static final String DB_NAME = "jdbc:sqlite:passDB.sqlite";

    private static final Connection CONNECTION;

    private static final String CREATE_PASSWORD_TABLE = "create table if not exists Passwords " +
            "(website varchar(150) not null, username varchar(50) not null, encryptedPassword varchar(300) not null, " +
            "salt varchar(16), primary key (website, username));";

    private static final String DROP_DATABASE = "drop table if exists Passwords;";

    private static final String INSERT_PASSWORD_RECORD = "insert into Passwords values (?, ?, ?, ?);";

    private static final String SELECT_PASSWORD_RECORDS = "select * from Passwords;";

    private static final String SELECT_WEBSITE_AND_USERNAME = "select website, username from Passwords;";

    private static final String DELETE_PASSWORD_RECORD = "delete from Passwords where website = ? and username = ?;";

    // establish connection and statement
    static {
        try {
            CONNECTION = DriverManager.getConnection(DB_NAME);
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Saves a {@link AccountRecord} into the database.
     *
     * @param record {@link AccountRecord} to be saved.
     * @return boolean if save was successful.
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     * @throws SQLException
     */
    public static void savePassword(AccountRecord record)
            throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException,
            NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, SQLException, DuplicateAccountException {
        // make sure table exists
        createPasswordsTable();

        // check for duplicate website and username
        PreparedStatement ps = CONNECTION.prepareStatement(SELECT_WEBSITE_AND_USERNAME);
        ps.execute();
        ResultSet rs = ps.getResultSet();

        // loop through select results
        while (rs.next()) {
            if (record.website.equals(rs.getString("website")) && record.username.equals(rs.getString("username"))) {
                throw new DuplicateAccountException("Duplicate account.");
            }
        }

        // generate salt
        byte[] salt = EncryptionTools.generateSalt();

        // encrypt password
        char[] encryptedPass = EncryptionTools.encryptUserPassword(MainGUI.masterPassword, record.password, salt);

        // add to database
        ps = CONNECTION.prepareStatement(INSERT_PASSWORD_RECORD);
        ps.setString(1, record.website);
        ps.setString(2, record.username);
        ps.setString(3, new String(encryptedPass));
        ps.setBytes(4, salt);

        ps.execute();
    }

    /**
     * Finds {@link AccountRecord}s with matching website name.
     *
     * @param website {@link String} website to search for.
     * @return {@link ArrayList} of PasswordRecords.
     * @throws SQLException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     */
    public static ArrayList<AccountRecord> findPasswordRecordsWithWebsite(String website) throws SQLException,
            InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException,
            NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        ArrayList<AccountRecord> returnList = new ArrayList<>();

        ArrayList<EncryptedAccountRecord> encryptedAccountRecords = getEncryptedPasswordRecords();

        for (EncryptedAccountRecord record :
                encryptedAccountRecords) {
            if (website.equals(record.website)) {
                // decrypt password
                char[] decryptUserPassword = EncryptionTools.decryptUserPassword(MainGUI.masterPassword,
                        record.encryptedPassword, record.salt);

                returnList.add(new AccountRecord(record.website, record.username, decryptUserPassword));
            }
        }

        return returnList;
    }

    /**
     * Finds {@link AccountRecord}s with matching website name.
     *
     * @param username {@link String} username to search for.
     * @return {@link ArrayList} of PasswordRecords.
     * @throws SQLException
     * @throws InvalidAlgorithmParameterException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws NoSuchAlgorithmException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     */
    public static ArrayList<AccountRecord> findPasswordRecordWithUsername(String username) throws SQLException,
            InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException,
            NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        ArrayList<AccountRecord> returnList = new ArrayList<>();

        ArrayList<EncryptedAccountRecord> encryptedAccountRecords = getEncryptedPasswordRecords();

        for (EncryptedAccountRecord record :
                encryptedAccountRecords) {
            if (username.equals(record.username)) {
                // decrypt password
                char[] decryptUserPassword = EncryptionTools.decryptUserPassword(MainGUI.masterPassword,
                        record.encryptedPassword, record.salt);

                returnList.add(new AccountRecord(record.website, record.username, decryptUserPassword));
            }
        }

        return returnList;
    }

    /**
     * Deletes {@link AccountRecord} from database.
     *
     * @param accountRecord {@link AccountRecord} to be deleted.
     * @return boolean if delete was successful.
     * @throws SQLException
     */
    public static boolean deletePasswordRecord(AccountRecord accountRecord) throws SQLException {
        PreparedStatement ps = CONNECTION.prepareStatement(DELETE_PASSWORD_RECORD);
        ps.setString(1, accountRecord.website);
        ps.setString(2, accountRecord.username);

        return ps.execute();
    }

    /**
     * Deletes entire password table from database.
     *
     * @return boolean if deletion was successful.
     * @throws SQLException
     */
    public static boolean deletePasswordDatabase() throws SQLException {
        PreparedStatement ps = CONNECTION.prepareStatement(DROP_DATABASE);
        return ps.execute();
    }

    /**
     * Gets all {@link EncryptedAccountRecord}s from database.
     *
     * @return {@link ArrayList} of {@link EncryptedAccountRecord}.
     * @throws SQLException
     */
    private static ArrayList<EncryptedAccountRecord> getEncryptedPasswordRecords() throws SQLException {
        PreparedStatement ps = CONNECTION.prepareStatement(SELECT_PASSWORD_RECORDS);
        ps.execute();
        ResultSet rs = ps.getResultSet();

        // create list
        ArrayList<EncryptedAccountRecord> list = new ArrayList<>();

        // loop through select results
        while (rs.next()) {
            // create new Record
            EncryptedAccountRecord record = new EncryptedAccountRecord(rs.getString("website"),
                    rs.getString("username"),
                    rs.getString("encryptedPassword").toCharArray(),
                    rs.getBytes("salt"));

            list.add(record);
        }

        return list;
    }

    /**
     * Attempts to create password table in database. Will do nothing if table already exists.
     *
     * @throws SQLException
     */
    private static void createPasswordsTable() throws SQLException {
        // create tables
        PreparedStatement ps = CONNECTION.prepareStatement(CREATE_PASSWORD_TABLE);
        ps.execute();
    }

    public static class DuplicateAccountException extends Exception {
        public DuplicateAccountException(String s) {
            super(s);
        }
    }

    /**
     * Record to contain un-encrypted password information.
     *
     * @param website  {@link String} name of website.
     * @param username {@link String} username of account.
     * @param password {@link String} password of account.
     */
    public record AccountRecord(String website, String username, char[] password) {

        public AccountRecord {
            // check null and blank
            if (website == null || website.isBlank()) {
                throw new IllegalArgumentException("Website cannot be blank or null.");
            }
            if (username == null || username.isBlank()) {
                throw new IllegalArgumentException("Username cannot be blank or null.");
            }
            if (password == null || password.length == 0) {
                throw new IllegalArgumentException("Password cannot be null or empty.");
            }

            // check max length
            if (website.length() > 150) {
                throw new IllegalArgumentException("Website cannot be longer than 150 character.");
            }
            if (username.length() > 50) {
                throw new IllegalArgumentException("Username cannot be longer than 50 character.");
            }
        }

        @Override
        public String toString() {
            return "Website: " + website + '\n' +
                    "Username: " + username + '\n' +
                    "Password: " + new String(password);
        }
    }

    public record EncryptedAccountRecord(String website, String username, char[] encryptedPassword, byte[] salt) {
        public EncryptedAccountRecord {
            // check null and blank
            if (website == null || website.isBlank()) {
                throw new IllegalArgumentException("Website cannot be blank or null.");
            }
            if (username == null || username.isBlank()) {
                throw new IllegalArgumentException("Username cannot be blank or null.");
            }
            if (encryptedPassword == null || encryptedPassword.length == 0) {
                throw new IllegalArgumentException("Password cannot be null or empty.");
            }
            if (salt == null || salt.length == 0) {
                throw new IllegalArgumentException("Salt cannot be null or empty.");
            }

            // check max length
            if (website.length() > 150) {
                throw new IllegalArgumentException("Website cannot be longer than 150 character.");
            }
            if (username.length() > 50) {
                throw new IllegalArgumentException("Username cannot be longer than 50 character.");
            }
        }

        @Override
        public String toString() {
            return "Website: " + website + '\n' +
                    "Username: " + username + '\n' +
                    "Encrypted Password: " + new String(encryptedPassword) +
                    "Salt: " + new String(salt);
        }
    }
}
