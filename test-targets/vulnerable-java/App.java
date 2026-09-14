import java.io.*;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import java.sql.*;
import java.util.Random;

public class App {
    static String API_KEY = "sk_live_abcdEFGH12345678";

    static void runCommand(String userInput) throws IOException {
        Runtime.getRuntime().exec("echo " + userInput);
    }

    static Object loadSession(InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        return ois.readObject();
    }

    static javax.xml.parsers.DocumentBuilder buildParser() throws Exception {
        javax.xml.parsers.DocumentBuilderFactory dbf = javax.xml.parsers.DocumentBuilderFactory.newInstance();
        return dbf.newDocumentBuilder();
    }

    static String weakHash(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return new String(md.digest(input.getBytes()));
    }

    static byte[] weakEncrypt(byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("DES");
        return c.doFinal(data);
    }

    static ResultSet runQuery(Connection conn, String table) throws SQLException {
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM " + table + " WHERE active=1";
        return stmt.executeQuery(query);
    }

    static String genToken() {
        Random r = new Random();
        return String.valueOf(r.nextInt());
    }
}
