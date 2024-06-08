# Usage

## Getting help
    - Run makefile with command <make>
    - Run program stockholm with command <./stockholm -h> OR <./stockholm --help>
## Printing version
    - Run makefile with command <make>
    - Run program stockholm with command <./stockholm -v> OR <./stockholm --version>
## Encrypting files
    - Run makefile with command <make>
    - Run program stockholm with command <./stockholm>. NO ARGUMENTS ARE PROVIDED FOR THIS CASE
## Decrypting files
    - Run makefile with command <make>
    - Use command <openssl pkeyutl -decrypt -in encryptedKey.txt -inkey rsaPriv.txt > decrypted.key>
    - Run program stockholm with command <./stockholm -r decrypted.key> OR <./stockholm --reverse decrypted.key>
