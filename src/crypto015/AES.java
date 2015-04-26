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
import java.security.SecureRandom;
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
import org.apache.commons.codec.binary.Base64;
import sun.misc.BASE64Encoder;

/**
 *
 * @author Ettore Ciprian <cipettaro@gmail.com>
 */
public class AES {

    private int key_size;
    private SecretKey key;

    public AES() {
        this.key_size = 256; //default set to 256 bit
        this.key = null;
    }

    public int getKeySize() {
        return key_size;
    }

    public void setKeySize(int key_size) {
        this.key_size = key_size;
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
        setKey(keyGen.generateKey());
        return getKey();
    }

    /**
     * Encrytp message given
     *
     * @param message - Input text to be encrypted
     * @param key - Key for encryption
     * @param mode -
     * @return
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     */
    public String encrypt(String message, String key, String mode) throws InvalidKeyException, InvalidAlgorithmParameterException {
        byte[] iv = new byte[16];//Initialization vector

        Cipher cipher = null;
        try {
            switch (mode) {
                case "CBC":
                    iv = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
                    cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");//Use PKCS5Padding to handle input not mutiple of 16
                    break;
                case "CFB":
                    iv = (new SecureRandom()).generateSeed(16);
                    cipher = Cipher.getInstance("AES/CFB/PKCS5Padding");
                    break;
                default:
            }

        } catch (NoSuchAlgorithmException | NoSuchPaddingException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        }

        byte[] encodedKey = Base64.decodeBase64(key);

        SecretKey originalKey = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, originalKey, ivspec);

        byte[] encrypted = null;
        try {
            encrypted = cipher.doFinal(message.getBytes());
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        }
        System.out.println("Ciphertext: " + toHex(encrypted) + "\n");
        return toHex(encrypted);
    }

    /**
     * Print the random generated key to a file
     *
     * @param path {String} - Path where to save the key
     */
    public void printKeytoFile(String path) {

        byte[] encoded = generateKey().getEncoded();
        try (PrintWriter writer = new PrintWriter(path, "UTF-8")) {
            System.out.println(this.getKeySize() + " bit key: ");
            String encodedKey = toHex(encoded);
            System.out.println(encodedKey);
            writer.print(encodedKey);
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
            System.out.println("File path: " + keyfile.getCanonicalPath() + "\nI have got this key: " + toHex(keybyte));
        } catch (IOException ex) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, ex);
        }
        return new SecretKeySpec(keybyte, "AES");
    }

    /**
     * *
     * Encode to hex a byte array
     *
     * @param data
     * @return the resulting String
     */
    public String toHex(byte[] input) {
        if (input == null || input.length == 0) {
            return "";
        }

        int inputLength = input.length;
        StringBuilder output = new StringBuilder(inputLength * 2);

        for (int i = 0; i < inputLength; i++) {
            int next = input[i] & 0xff;
            if (next < 0x10) {
                output.append("0");
            }

            output.append(Integer.toHexString(next));
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
