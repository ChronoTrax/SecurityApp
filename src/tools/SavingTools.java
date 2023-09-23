package tools;

import java.sql.*;
import java.util.ArrayList;

public class SavingTools {
    private static final String DB_NAME = "jdbc:sqlite:passDB.sqlite";
    private static final Connection CONNECTION;
    private static final Statement STATEMENT;

    // establish connection and statement
    static {
        try {
            CONNECTION = DriverManager.getConnection(DB_NAME);
            STATEMENT = CONNECTION.createStatement();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public record PasswordRecord(String website, String username, String password) {

    }

    private static final String CREATE_DATABASE = "create table if not exists Passwords (website varchar(150) not null primary key, username varchar(50) not null, password varchar(50) not null);";

    private static final String DROP_DATABASE = "drop table if exists Passwords;";

    private static final String INSERT_PASSWORD_RECORD = "insert into Passwords values ('%s', '%s', '%s');";
    private static final String SELECT_PASSWORD_RECORDS = "select * from Passwords;";

    public static boolean savePassword(PasswordRecord record) throws SQLException {
        // check null or blank
        if (record.website == null || record.website.isBlank() ||
                record.username == null || record.username.isBlank() ||
                record.password == null || record.password.isBlank()) {
            throw new RuntimeException("Website, username, and password cannot be blank.");
        }

        // check website length
        if (record.website.length() > 150) {
            throw new RuntimeException("Website cannot be longer than 150 character.");
        }

        // check username and password length
        if (record.website.length() > 50) {
            throw new RuntimeException("Username and password cannot be longer than 50 character.");
        }

        // make sure table exists
        createTables();

        // add to database
        STATEMENT.execute(INSERT_PASSWORD_RECORD.formatted(record.website, record.username, record.password));

        return true;
    }

    public static PasswordRecord findPasswordRecordWithWebsite(String website) throws SQLException {
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

    public static PasswordRecord findPasswordRecordWithUsername(String username) throws SQLException {
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

    private static ArrayList<PasswordRecord> getPasswordRecords() throws SQLException {
        STATEMENT.execute(SELECT_PASSWORD_RECORDS);
        ResultSet rs = STATEMENT.getResultSet();

        // create list
        ArrayList<PasswordRecord> list = new ArrayList<>();

        // loop through select results
        while (rs.next()) {
            // create new Record
            PasswordRecord record = new PasswordRecord(rs.getString("website"),
                    rs.getString("username"), rs.getString("password"));

            list.add(record);
        }

        return list;
    }

    private static void createTables() throws SQLException {
        // create tables
        STATEMENT.execute(CREATE_DATABASE);
    }
}
