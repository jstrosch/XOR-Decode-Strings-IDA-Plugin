# Simple IDA Python Plugin to Decode XOR Strings

This plugin was inspired by a recent XLS document that drops and executes a DLL using RUNDLL32. The DLL is small and only used to download the next stage. However, it employs rather straight-forward string obfuscation using the bitwise XOR operation. An important skill for any reverse engineer/malware analyst is to be able to create plugins to assist in statically decoding these strings and doing so across the entire disassembly database. This plugin is intended to get you started creating IDA Plugins with Python, recognize the importance of deobfuscating strings and work on translating assembly to a higher-level language (i.e. Python).

Original sample and DLL: [https://github.com/jstrosch/malware-samples/tree/master/maldocs/unknown/2020/December](https://github.com/jstrosch/malware-samples/tree/master/maldocs/unknown/2020/December)  
Analysis on YouTube: [https://youtu.be/un8I6dfuDVQ](https://youtu.be/un8I6dfuDVQ)

## Obfuscated Strings

Below is a sample of the obfsucated string pattern. The function called to deobfucate the strings is *sub_10001210* and takes three arguments - the size of the string to decode, the key and obfuscated string (in that order).

![Obfuscated strings](https://user-images.githubusercontent.com/1920756/102287860-efc2c100-3f00-11eb-9ea0-4ddc8681d74e.png)

Function *sub_10001210* allocates memory for the deobfuscated string using *LocallAloc* and a loop. The loop takes each letter of the key and XORs with the obfuscated string. If the string is longer than the key, it uses modulo division to repeat back over the key and continue until the string is full deobfuscated.

![XOR Loop](https://user-images.githubusercontent.com/1920756/102287869-f3564800-3f00-11eb-8279-238599616fbb.png)

Finally, the pointer to the allocated memory that contains the deobfucated string is returned and assigned to a global variable. The default behavior for this plugin is to add the deobfuscated string value as a comment next to this assignment.

![Deobfuscated](https://user-images.githubusercontent.com/1920756/102287873-f4877500-3f00-11eb-8f20-19d2826e4414.png)

This plugin is not intended to decode all XOR obfuscated strings you encounter, but should serve as a good starting point to implement the logic you encounter and recover those strings!