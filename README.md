# Cahir
A deterministic password manager.

![cahir](https://github.com/samuel-lucas6/Cahir/assets/63159663/e3f078d6-99f5-43e4-b30a-daa4274a7822)

## Installation
On Windows, Linux, and macOS (x64 and ARM64), you can use the pre-built binaries:
```
https://github.com/samuel-lucas6/Cahir/releases
```

If your system has the [latest .NET 8 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/8.0), you can build from source (replace `RID` with [your platform](https://learn.microsoft.com/en-us/dotnet/core/rid-catalog#known-rids)):
```
$ cd src
$ dotnet publish -r RID -c Release
```

If you try to use your YubiKey on Linux, you'll likely get an error mentioning `libudev.so`. To get things working, you must [create a symbolic link](https://docs.yubico.com/yesdk/users-manual/getting-started/running-on-linux.html#udev) from `libudev.so.1` to the directory .NET is using for Cahir. On Debian-based distros, the command will look something like this:
```
$ sudo ln -s /usr/lib/x86_64-linux-gnu/libudev.so.1 /home/samuel/.net/cahir/ftlSfb7AS_XKCtW7BksiMKLSs1L2dYc=/libudev.so
```

## Usage
```
USAGE:
    cahir [OPTIONS]

EXAMPLES:
    cahir -i "alicejones@pm.me" -d "github.com"
    cahir -i "alicejones@pm.me" -d "github.com" -p "correct horse battery staple"
    cahir -i "+44 07488 855302" -d "github.com" -f "password.txt"
    cahir -i "+44 07488 855302" -d "github.com" -k "pepper.key"

OPTIONS:
    -i, --identity <IDENTITY>     Your unique identifier (e.g. email address)
    -d, --domain <DOMAIN>         The website domain (e.g. github.com)
    -p, --password <PASSWORD>     Your master password (omit for interactive entry)
    -f, --password-file <FILE>    Your master password stored as a file (omit for interactive entry)
    -k, --keyfile <FILE>          Your pepper stored as a file
    -g, --generate <FILE>         Randomly generate a keyfile with the specified file name
    -y, --yubikey [SLOT]          Use your YubiKey for challenge-response (defaults to slot 2)
    -m, --modify-slot [SLOT]      Set up a challenge-response YubiKey slot
    -c, --counter <COUNTER>       The counter for when a site password needs to be changed (default is 1)
    -l, --length <LENGTH>         The length of the derived site password (default is 20 characters or 8 words)
    -a, --lowercase               Include lowercase characters in the derived site password
    -u, --uppercase               Include uppercase characters in the derived site password
    -n, --numbers                 Include numbers in the derived site password
    -s, --symbols                 Include symbols in the derived site password
    -w, --words                   Derive a passphrase
    -v, --version                 Prints version information
    -h, --help                    Prints help information
```

## Specification
### Security Goals
- It should be difficult to brute force a master password.
- It should be computationally infeasible to brute force a pepper.
- It should not be possible to compromise the YubiKey secret key after generation.
- It should not be possible to overwrite the YubiKey slot without the access code.
- It should not be possible to perform YubiKey challenge-response without physical touch.
- A compromise of the master password, but not the pepper, should not allow derivation of site passwords.
- A compromise of the pepper, but not the master password, should not allow derivation of site passwords.
- A compromise of the master password and a pepper from a YubiKey challenge-response should be limited to the adversary being able to derive only one site password.
- Key material should be indistinguishable from random.
- Key material should be bound to context-specific information.
- Site password derivation should be free from modulo bias.
- Derived site passwords should be high in entropy.
- Derived site passwords should be completely different when derivation parameters change.
- Sensitive data should be wiped from memory after use.
- It should be possible to enter the master password without revealing the typed characters.
- It should be possible to enter a YubiKey slot access code without revealing the typed characters.

### Threat Model
Cahir aims for security against an adversary who does not have physical or remote access to the user's machine. With such access, security cannot be guaranteed because the adversary has compromised the device. For example, they can use hardware/software keyloggers, memory forensics, disk forensics, and so on. However, Cahir attempts to zero sensitive data to minimise the risk of retrieval from memory or disk, and there is some protection against shoulder surfing.

To guess user inputs, the adversary must either perform:
1. An online attack against a specific site, which should be hindered by rate limiting and Cahir's password hashing/pepper derivation.
2. An offline attack against a specific program, which should be hindered by the program's and Cahir's password hashing/pepper derivation.
3. An offline attack against a specific derived site password, which requires a derived site password to be leaked and should be hindered by Cahir's password hashing/pepper derivation.

For security, we assume that:
- The user specifies a unique identifier.
- The user chooses a high entropy master password.
- The user generates the pepper using built-in functionality.
- The user keeps the master password/pepper secret.
- The user maintains possession of their YubiKey.
- Secrets cannot be extracted from YubiKeys.
- The user derives site passwords of adequate length/complexity.
- The OS CSPRNG produces cryptographically secure random numbers.
- The Monocypher cryptographic library does not have any vulnerabilities.
- The cryptographic algorithms are secure.
- There are no vulnerabilities in Cahir.

### Cryptographic Algorithms
- Argon2id for password-based key derivation, as described in [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html).
- BLAKE2b for hashing and keyed hashing, as described in [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693.html).
- ChaCha20 for key derivation, as described in [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html).
- HMAC-SHA1 for YubiKey challenge-response, as described in [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104).

### Master Key Derivation
```
salt = BLAKE2b-256(context || identity)
masterKey = Argon2id(password, salt, memorySize, passes, parallelism)
```
- `context`: the UTF-8 encoding of `"cahir.salt"` (10 bytes).
- `identity`: the UTF-8 encoding of the `-i, --identity` string (1+ bytes).
- `password`: the UTF-8 encoding of the `-p, --password` or interactively entered password string, which cannot be empty and is limited to 128 characters, or the bytes stored in the `-f, --password-file` file (1-387 bytes).
- `salt`: the salt derived above (32 bytes).
- `memorySize`: 512 MiB.
- `passes`: 3 passes.
- `parallelism`: 1 lane.

### Pepper Derivation
#### Keyfile
```
pepper = BLAKE2b-256(context || keyfile)
```
- `context`: the UTF-8 encoding of `"cahir.keyfile"` (13 bytes).
- `keyfile`: the bytes stored in the `-k, --keyfile` file (1+ bytes).

#### YubiKey
```
challenge = BLAKE2b-256(key: masterKey, message: context || counter || length || characterSet || domain)
```
- `masterKey`: the key from master key derivation (32 bytes).
- `context`: the UTF-8 encoding of `"cahir.challenge"` (15 bytes).
- `counter`: the little-endian encoding of the unsigned 32-bit `-c, --counter` integer (4 bytes).
- `length`: the little-endian encoding of the unsigned 32-bit `-l, --length` integer (4 bytes).
- `characterSet`: a single `0x01` or `0x00` byte (representing true or false respectively) for `-a, --lowercase`, `-u, --uppercase`, `-n, --numbers`, `-s, --symbols`, and `-w, --words` in that order (5 bytes).
- `domain`: the UTF-8 encoding of the `-d, --domain` string (1+ bytes).

```
response = HMAC-SHA1(key: yubikeySecret, message: challenge || padding)
pepper = BLAKE2b-256(key: response, message: context)
```
- `yubikeySecret`: the secret key stored on the YubiKey in an OTP slot (20 bytes).
- `challenge`: the challenge derived above (32 bytes).
- `padding`: an all-zero buffer (32 bytes).
- `response`: the HMAC-SHA1 output (20 bytes).
- `context`: the UTF-8 encoding of `"cahir.response"` (14 bytes).

### Site Key Derivation
```
siteKey = BLAKE2b-256(key, message: context || counter || length || characterSet || domain)
```
- `key`: the `masterKey` from master key derivation or `masterKey || pepper` if a keyfile or YubiKey challenge-response is used (32 or 64 bytes).
- `context`: the UTF-8 encoding of `"cahir.sitekey"` (13 bytes).
- `counter`: the little-endian encoding of the unsigned 32-bit `-c, --counter` integer (4 bytes).
- `length`: the little-endian encoding of the unsigned 32-bit `-l, --length` integer (4 bytes).
- `characterSet`: a single `0x01` or `0x00` byte (representing true or false respectively) for `-a, --lowercase`, `-u, --uppercase`, `-n, --numbers`, `-s, --symbols`, and `-w, --words` in that order (5 bytes).
- `domain`: the UTF-8 encoding of the `-d, --domain` string (1+ bytes).

### Site Password Derivation
```
ciphertext = ChaCha20(plaintext, nonce, key, counter)

if lowercase
    characterSet += "abcdefghijklmnopqrstuvwxyz"

if uppercase
    characterSet += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

if numbers
    characterSet += "0123456789"

if symbols
    characterSet += "!#$%&'()*+,-./:;<=>?@[]^_`{}~"

for i = 0 to length
    randomIndex = LE128(ciphertext.Slice(start: i * 16, length: 16)) % characterSet.Length
    sitePassword[i] = characterSet[randomIndex]
```
- `plaintext`: an all-zero buffer (`-l, --length` * 16 bytes).
- `nonce`: the UTF-8 encoding of `"cahir.sitepw"` (12 bytes).
- `key`: the `siteKey` from site key derivation (32 bytes).
- `counter`: an unsigned 32-bit integer equal to 0.
- `lowercase`: whether `-a, --lowercase` was specified.
- `uppercase`: whether `-u, --uppercase` was specified.
- `numbers`: whether `-n, --numbers` was specified.
- `symbols`: whether `-s, --symbols` was specified.
- `length`: the `-l, --length` integer.
- `randomIndex`: an unsigned 128-bit integer converted to a signed 32-bit integer.

### Site Passphrase Derivation
```
ciphertext = ChaCha20(plaintext, nonce, key, counter)

offset = 0
characterSet = "0123456789"
randomNumber = 0
randomPosition = 0
if numbers
    offset = 2
    randomNumber = LE128(ciphertext.Slice(start: 0, length: 16)) % characterSet.Length
    randomPosition = LE128(ciphertext.Slice(start: 16, length: 16)) % wordCount

count = 0
wordlist = BIP39.Split("\n")
for i = 0 to wordCount
    randomIndex = LE128(ciphertext.Slice(start: (i + offset) * 16, length: 16)) % wordlist.Length
    word = wordlist[randomIndex]

    for j = 0 to word.Length
        if uppercase and j == 0
            sitePassphrase[count] = word[j].ToUpper()
        else
            sitePassphrase[count] = word[j]
        count++

    if numbers and i == randomPosition
        sitePassphrase[count] = characterSet[randomNumber]
        count++

    if i != wordCount - 1
        if symbols
            sitePassphrase[count] = "-"
        else
            sitePassphrase[count] = " "
        count++
```
- `plaintext`: an all-zero buffer (`-l, --length` * 16 bytes or (`-l, --length` + 2) * 16 bytes if `-n, --numbers`).
- `nonce`: the UTF-8 encoding of `"cahir.sitepp"` (12 bytes).
- `key`: the `siteKey` from site key derivation (32 bytes).
- `counter`: an unsigned 32-bit integer equal to 0.
- `randomNumber`: an unsigned 128-bit integer converted to a signed 32-bit integer.
- `randomPosition`: an unsigned 128-bit integer converted to a signed 32-bit integer.
- `wordCount`: the `-l, --length` integer.
- `wordlist`: a string array created by splitting the [BIP39 English wordlist](https://github.com/bitcoin/bips/blob/master/bip-0039/bip-0039-wordlists.md) by newline.
- `randomIndex`: an unsigned 128-bit integer converted to a signed 32-bit integer.
- `uppercase`: whether `-u, --uppercase` was specified.
- `numbers`: whether `-n, --numbers` was specified.
- `symbols`: whether `-s, --symbols` was specified.
