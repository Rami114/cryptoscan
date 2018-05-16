BinaryNinja CryptoScan
======================
Plugin for [Binary Ninja](https://binary.ninja/) platform

## General
This Binja plugin is effectively trying to replicate [findcrypt](https://github.com/you0708/ida/tree/master/idapython_tools/findcrypt) functionality. It supports a larger range of constants.

## Features
### Overview
The plugin registers a single call that is accessible from the 'Tools' menu or by right-clicking in the main binary view window. 

Scan configurations are reloaded on _every_ call to the scan function. This means you can CRUD json config files and rescan immediately. 

The plugin supports the following types of scans:

 - Scanning for constants in data 
 - Scanning for constants in the IL 

### Supported cryptography

The following constants are defined in scan configurations:

 - AES: sboxes, td0-4, te0-4
 - ARIA: sbox2, sbox4 (1 and 3 are equal to Rijndael)
 - BLAKE: 224, 256, 384 and 512 inits 
 - Blowfish: p_array and sbox
 - CRC32: lzma tables 0-7, m_tab_le and m_tab_be, ms_table0-6
 - DES: p32i, pc1_left, pc1_right, pc2, sbox1-8
 - DFC: sbox
 - Elliptic Curves: p-192, p-224, p-256, p-384, p-521, Curve25519
 - IKE: modp group shared component
 - KASUMI: key expansion mod, sbox_s7, sbox_s9
 - MD5: initstate and md5_t
 - NewDES: sbox
 - RC5/RC6: combined constant
 - SHA1: h
 - SHA224: h
 - SHA256: both k and h 
 - SHA512: h
 - SM3: init
 - SM4: sbox, ck and fk
 - TEA: delta
 - Zlib: distance_starts, distance_extrabits, length_starts, length_extrabits

### Reporting
If any matches are identified a Markdown (for GUI) or text (for CLI) report will be shown, listing which scans were matched, what family they belong to as well as the address in the binary.
The aim of the report was to allow easy copy-pasting of the address for use with the 'Go to address...' function. 

Whilst data matches only contain the address at which the constant is defined, IL matches will also indicate the function they were discovered in.

### Configuration
Individual scan configurations are kept in the scans subfolder. The following fields are required in the JSON:

 - name: short name for the scan
 - description: long name or description, only for author's quality of life 
 - threshold: for multi-byte constants, minimum amount of n-sized chunks that must be found (e.g. when loading chunked in registers) 
 - type: static or signature (signatures are currently not implemented though)
 - flags: array of single byte strings, usually 4 bytes but no upper bound is set. You can now add null bytes. 
 - on_match: object with subfields
   - type: symbol is the only supported value right now, adds a symbol at the detected address
   - name: name to give to the symbol

## TODO
- [x] Add more constants 
- [x] Make CryptoScan run in the background
- [x] Deal with null bytes in the flags better
- [ ] Flesh out how signature detection will work
- [ ] Refactor data scanning to improve speed on very large binaries 
