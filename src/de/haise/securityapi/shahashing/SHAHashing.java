package de.haise.securityapi.shahashing;

import de.haise.securityapi.salt.Salt;
import de.haise.securityapi.shahashing.SHAHashingType;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHAHashing {

    String string;
    SHAHashingType shaHashingType;

    public void SHAHashing(String string, SHAHashingType shaHashingType) {
        this.string = string;
        this.shaHashingType = shaHashingType;
    }

    private String getSecurePassword()
    {
        String generatedPassword = null;
        MessageDigest md;
        StringBuilder sb;
        byte[] bytes;
        try {
            switch (shaHashingType) {
                case SHA_1:
                    md = MessageDigest.getInstance("SHA-1");
                    break;
                case SHA_256:
                    md = MessageDigest.getInstance("SHA-256");
                    break;
                case SHA_384:
                    md = MessageDigest.getInstance("SHA-384");
                    break;
                case SHA_512:
                    md = MessageDigest.getInstance("SHA-512");
                    break;
                default:
                    throw new IllegalStateException("Unexpected value: " + shaHashingType);
            }
            md.update(Salt.getSalt());
            bytes = md.digest(string.getBytes());
            sb = new StringBuilder();
            for(int i=0; i< bytes.length ;i++)
            {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            generatedPassword = sb.toString();
        }
        catch (NoSuchAlgorithmException e)
        {
            e.printStackTrace();
        }
        return generatedPassword;
    }

}
