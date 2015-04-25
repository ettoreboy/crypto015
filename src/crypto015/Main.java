package crypto015;

import java.io.FileNotFoundException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Paths;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Ettore Ciprian <cipettaro@gmail.com>
 */
public class Main {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        AES aes = new AES();
        switch (args[0]) {

            case "--generate-key":

                if (args.length < 2) {
                    System.err.println("Please provide a path where to save the key");
                    System.exit(1);
                } else {
                    if (args.length < 3) {
                        aes.printKeytoFile(args[1]);
                    } else if (!args[2].matches("(128|192|256)")) {
                        System.err.println("Please provide a valid key size (128, 192 or 256)");
                        System.exit(1);
                    } else {
                        aes.setKeySize(Integer.parseInt(args[2]));
                        aes.printKeytoFile(args[1]);
                    }

                }

                break;
            case "--read-key":
                if (args.length < 2) {
                    System.err.println("Please provide the key path");
                    System.exit(1);
                } else {
                    aes.loadKeyfromFile(Paths.get(args[1]).toFile());
                }
                break;
            case "--encrypt-cbc":

                break;
            case "--encrypt-cfb":
                break;

            case "--decrypt":
                break;

            default:
                System.err.println("Please provide a valid command!");
                System.exit(1);

        }
        System.out.println();
        System.exit(0);

    }
}
