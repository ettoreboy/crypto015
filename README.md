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
+ ``` --read-key [PATH]```

   Read a key from a given file
+ ```--encrypt INPUT_PATH OUTPUT_PATH [KEY] [MODE] ```

  Encrypt an input file to an output file
  and an output path.

  *INPUT_PATH* - File path for the input

  *OUTPUT_PATH* - File path to output, if not present it will be created

  *KEY* - Key for encryption

  *MODE* - Chaining mode. Either "CBC" or "CBF".

  Example usage: ``` ---encrypt C:\\Path\to\File.txt C:\\Output.txt "ansvsgxbsichfvns8590f" CBC```
