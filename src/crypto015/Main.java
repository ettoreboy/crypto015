package crypto015;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
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
            case "--encrypt":
                if (args.length < 3) {
                    System.err.println("Please provide correct arguments for encrypt operation: INPUT_PATH OUTPUT_PATH [KEY] [MODE]");
                    System.exit(1);
                } else if (!Paths.get(args[1]).toFile().canRead() || args[2] == null) {
                    System.err.println("Please provide valid paths! Program terminating..");
                    System.exit(1);
                } else {
                    String in = "";
                    try {
                        in = readFile(args[1], Charset.defaultCharset());
                    } catch (IOException ex) {
                        Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    if (args[3] == null) {
                        System.err.println("Please provide valid key path! Program terminating..");
                        System.exit(1);
                    } else {
                        String key = "";
                        try {
                            key = readFile(args[3], Charset.defaultCharset());
                        } catch (IOException ex) {
                            System.out.println("Please provide a valid key path! Program terminating..");
                            System.exit(1);
                        }
                        byte[] out = null;
                        try {
                            switch (args[4]) {
                                case "CBC": {
                                    out = aes.encrypt(in, key, "CBC");
                                    break;
                                }
                                case "CFB": {
                                    out = aes.encrypt(in, key, "CFB");
                                    break;
                                }
                                default:
                                    System.err.println("Please provide a valid ncryption mode (CBC|CFB)! Program terminating..");
                                    System.exit(1);
                            }
                            Path outputPath = Paths.get(args[2]);
                            Files.createFile(outputPath);
                            FileOutputStream outStream = new FileOutputStream(outputPath.toFile());
                            outStream.write(out);
                            outStream.close();
                        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IOException ex) {
                            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
                }

                break;

            case "--decrypt":
                if (args.length < 3) {
                    System.err.println("Please provide correct arguments for decrypt operation: INPUT_PATH OUTPUT_PATH [KEY] [MODE]");
                    System.exit(1);
                } else if (!Paths.get(args[1]).toFile().canRead() || args[2] == null) {
                    System.err.println("Please provide valid paths! Program terminating..");
                    System.exit(1);
                } else {
                    byte[] in = null;
                    try {
                        in = readFile(args[1]);
                    } catch (IOException ex) {
                        Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    if (args[3] == null) {
                        System.err.println("Please provide valid key path! Program terminating..");
                        System.exit(1);
                    } else {
                        String out = "";
                        String key = "";
                        try {
                            key = readFile(args[3], Charset.defaultCharset());
                        } catch (IOException ex) {
                            System.out.println("Please provide a valid key path! Program terminating..");
                            System.exit(1);
                        }
                        try {
                            switch (args[4]) {
                                case "CBC": {
                                    out = aes.decrypt(in, key, "CBC", null);
                                    break;
                                }
                                case "CFB": {
                                    if (args[5] != null) {
                                        out = aes.decrypt(in, key, "CFB", AES.toByteArray(args[5]));
                                    }
                                    break;
                                }
                                default:
                                    System.err.println("Please provide a valid decryption mode (CBC|CFB)! Program terminating..");
                                    System.exit(1);
                            }
                            Path outputPath = Paths.get(args[2]);
                            Files.createFile(outputPath);
                            FileOutputStream outStream = new FileOutputStream(outputPath.toFile());
                            outStream.write(out.getBytes());
                            outStream.close();
                        } catch (InvalidKeyException | InvalidAlgorithmParameterException | IOException ex) {
                            Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
                        }
                    }
                }
                break;

            default:
                System.err.println("Please provide a valid command! Program terminating..");
                System.exit(1);

        }
        System.out.println();
        System.exit(0);

    }

    /**
     * Read file to single String
     *
     * @param path
     * @param encoding
     * @return String
     * @throws IOException
     */
    private static String readFile(String path, Charset encoding)
            throws IOException {
        byte[] encoded = Files.readAllBytes(Paths.get(path));
        return new String(encoded, encoding);
    }

    private static byte[] readFile(String path)
            throws IOException {

        return Files.readAllBytes(Paths.get(path));
    }
}
