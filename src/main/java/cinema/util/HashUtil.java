package cinema.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class HashUtil {
    public static final String HASH_ALGORITHM = "SHA-512";

    private HashUtil() {

    }

    public static String hashPassword(String password, byte[] salt) {
        StringBuilder hashedPassword = new StringBuilder();
        try {
            MessageDigest messageDigest = MessageDigest.getInstance(HASH_ALGORITHM);
            messageDigest.update(salt);
            byte[] digest = messageDigest.digest(password.getBytes());
            for (byte byteOfPassword : digest) {
                hashedPassword.append(String.format("%02x", byteOfPassword));
            }
            return hashedPassword.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Could not create hash using " + HASH_ALGORITHM
                    + " algorithm", e);
        }
    }

    public static byte[] getSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }
}
