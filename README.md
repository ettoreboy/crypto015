# crypto015
A simple java implementation of AES and CBC/CFB using the Java SDK

##Usage
Before proceeding make sure you have downloaded the jurisdiction policy for your respective Java platform from over here. Place the policy files in the {JDK_HOME}\jre\lib\security folder. (Usually already present from Java SDK 1.4).

Using the this tool it's easy, compile it or use the pre-compiled */dist/crypto015.jar* in **dist.zip** file
```bash
java -jar crypto015.jar [OPTION...]
```

##Options
+ ``` --generate-key PATH [KEY_SIZE] ```

   Print the key to the specified path, the key size (128|192|256) can be set, default is 256.

+ ```--encrypt INPUT_PATH OUTPUT_PATH [KEY] [MODE] ```

  Encrypt an input file to an output file
  and an output path.

  *INPUT_PATH* - File path for the input

  *OUTPUT_PATH* - File path to output. **NOTE:** If not present it will be created, otherwise it will be overwritten.

  *KEY_PATH* - Path to file containing the key for encryption

  *MODE* - Chaining mode. Either "CBC" or "CFB".
    **NOTE:** If CFB is selected, a random initializiation vector will be provided.
  Example usage: ``` ---encrypt C:\\Path\to\File.txt C:\\Output.txt C:\\key.txt CBC```
+ ``` --decrypt INPUT_PATH OUTPUT_PATH KEY_PATH MODE [IV]```

   Decrypt a message given a key to an output text

   *INPUT_PATH* Input path of the ciphertext

   *OUTPUT_PATH* Output path for the decrypted text

   *KEY_PATH* Path to key file

   *MODE* Mode for decryption, either CBC or CFB

   *IV* (Optional) **NOTE:** If CFB was selected you must give the 16bit initialization vector (randomly generated during encryption).  
