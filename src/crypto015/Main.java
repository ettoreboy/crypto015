package crypto015;

import java.io.FileNotFoundException;
import java.io.UnsupportedEncodingException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Ettore Ciprian <cipettaro@gmail.com>
 */
public class Main {
 private static final AES aes = new AES(); 
    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {

        
        if (args.length > 0 && args[0].equals("--print-key")){
            if (!args[1].isEmpty()){
                try {
                    aes.printKeytoFile(args[1]);
                } catch (FileNotFoundException ex) {
                    Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
                    System.err.println("Please provide a valid path where to save the key");
                } catch (UnsupportedEncodingException ex) {
                    Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
                }
                
            } else {
                System.err.println("Please provide a path where to save the key");
                System.exit(1);
            }
                
            
        }
    }
    
}
