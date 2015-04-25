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
+ ```--encrypt-cbc INPUT_PATH OUTPUT_PATH [KEY_PATH] ```
