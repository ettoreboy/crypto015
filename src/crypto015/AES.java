/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package crypto015;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;

/**
 *
 * @author Ettore Ciprian <cipettaro@gmail.com>
 */
public class AES { 
   
 private final int KEYSIZE = 256; //key size 
 private final SecretKey SECRET_KEY = generateKey(); //final initial key
    /**
     * Generate a random secure Key with the KeyGenerator library standards
     *
     * @return SecretKey
     */
    public SecretKey generateKey() {
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        }
        keyGen.init(256); // for example
        SecretKey secretKey = keyGen.generateKey();

        return secretKey;
    }

    /**
     * Print the random generated key to a file
     *
     * @param path where to save the key
     * @throws java.io.FileNotFoundException
     * @throws java.io.UnsupportedEncodingException
     */
    public void printKeytoFile(String path) throws FileNotFoundException, UnsupportedEncodingException {
   
        byte[] encoded = SECRET_KEY.getEncoded(); 
        try (PrintWriter writer = new PrintWriter(path, "UTF-8")) {
            System.out.println("256 bit key: ");
            for (byte b : encoded){
               writer.printf("%2X", b); 
               System.out.printf("%2X", b);
            }
            writer.println();
            writer.close();
        }
       
    }

}
