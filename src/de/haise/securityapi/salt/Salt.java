package de.haise.securityapi.salt;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Salt {

    public static byte[] getSalt() throws NoSuchAlgorithmException
    {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return salt;
    }

}
