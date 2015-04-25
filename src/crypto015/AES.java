package crypto015;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

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

    public void encryptCBC(String message, SecretKey key) throws InvalidKeyException, InvalidAlgorithmParameterException {
        byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        }
        cipher.init(Cipher.ENCRYPT_MODE, generateKey(), ivspec);

        byte[] encrypted = null;
        try {
            encrypted = cipher.doFinal(message.getBytes());
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        }
        System.out.println("Ciphertext: " + encodeHex(encrypted) + "\n");

    }

    /**
     * Print the random generated key to a file
     *
     * @param path {String} - Path where to save the key
     */
    public void printKeytoFile(String path) {

        byte[] encoded = this.getKey().getEncoded();
        try (PrintWriter writer = new PrintWriter(path, "UTF-8")) {
            System.out.println(this.getKeySize() + " bit key: ");
            for (byte b : encoded) {
                writer.printf("%2X",b);
                System.out.printf("%2X", b);
            }
            writer.println();
            writer.close();
        } catch (FileNotFoundException | UnsupportedEncodingException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
            System.err.println("Please provide a valid path where to save the key");
        }

    }

    /**
     * Load the AES key of specified size from a file
     *
     * @param keyfile File meant for the key only
     * @return
     */
    public SecretKey loadKeyfromFile(File keyfile) {
        byte[] keybyte = new byte[(int) keyfile.length()];
        FileInputStream fin = null;
        try {
            fin = new FileInputStream(keyfile);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        }
        try {
            fin.read(keybyte);
        } catch (IOException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        try {
            System.out.println("File path: "+keyfile.getCanonicalPath()+"\nI have got this key: " + encodeHex(keybyte));
        } catch (IOException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        }
        return new SecretKeySpec(keybyte, "AES");
    }

    /**
     * *
     * Encode to hex a byte array
     *
     * @param code - the byte array
     * @return the resulting String
     */
    public String encodeHex(byte[] code) {
        if (code == null || code.length == 0) {
            return "";
        }
        StringBuilder output = new StringBuilder(code.length * 2);

        for (byte b : code) {
            if (b < 0x10) {
                output.append("0");
            }
            output.append(Integer.toHexString(0xff & b));
        }

        return output.toString();

    }

    public void demoEncryption() {

        String message = "This string contains a secret message.";
        System.out.println("Plaintext: " + message + "\n");

    }

    public void decrypt(String encoded_message) {

    }

}
