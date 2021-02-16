package de.haise.securityapi.pbehashing;

import de.haise.securityapi.salt.Salt;
import de.haise.securityapi.util.HashingUtil;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class PBEHashing {

    String string;

    public PBEHashing(String string) {
        this.string = string;
    }

    public String generateStorngPasswordHash(String password) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        int iterations = 1000;
        char[] chars = password.toCharArray();
        byte[] salt = Salt.getSalt();

        PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 64 * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte[] hash = skf.generateSecret(spec).getEncoded();
        return iterations + ":" + HashingUtil.toHex(salt) + ":" + HashingUtil.toHex(hash);
    }

}
