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
private int key_size;
private SecretKey key;

    
    public AES() {
        this.key_size = 256; //default set to 256 bit
        this.key = generateKey(); //Generate the key at start
    }

    
    public int getKeySize() {
        return key_size;
    }

    public void setKeySize(int key_size) {
        this.key_size = key_size;
        this.key = generateKey(); //Regenerate secure key
    }

    public SecretKey getKey() {
        return key;
    }

    public void setKey(SecretKey key) {
        this.key = key;
    }

    /**
     * Generate a random secure Key with the KeyGenerator library standards
     *
     * @param {int} size of the key
     * @return SecretKey
     */
    private SecretKey generateKey() {
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        }
        keyGen.init(this.getKeySize());
        return keyGen.generateKey();
    }

    /**
     * Print the random generated key to a file
     *
     * @param {String} path - Path where to save the key
     * @throws java.io.FileNotFoundException
     * @throws java.io.UnsupportedEncodingException
     */
    public void printKeytoFile(String path) throws FileNotFoundException, UnsupportedEncodingException {

        byte[] encoded = this.getKey().getEncoded();
        try (PrintWriter writer = new PrintWriter(path, "UTF-8")) {
            System.out.println(this.getKeySize()+" bit key: ");
            for (byte b : encoded) {
                writer.printf("%2X", b);
                System.out.printf("%2X", b);
            }
            writer.println();
            writer.close();
        }

    }

    /**
     *
     * @param {String} message - Message to be encrypted
     */
    public void encrypt(String message) {
        //TODO
    }

    public void decrypt(String encoded_message) {

    }

}
