# Cahir
A deterministic password manager.

![cahir](https://github.com/samuel-lucas6/Cahir/assets/63159663/d182ba52-11db-415d-9abb-711a52687dae)

## Usage
```
USAGE:
    cahir [OPTIONS]

OPTIONS:
                                  DEFAULT
    -i, --identity <IDENTITY>                Your unique identifier (e.g. full name, username, phone number)
    -d, --domain <DOMAIN>                    The website URL (e.g. https://github.com)
    -p, --password <PASSWORD>                Your master password (omit for interactive entry)
    -f, --password-file <FILE>               Your master password stored as a file (omit for interactive entry)
    -k, --keyfile <FILE>                     Your pepper stored as a file
    -g, --generate <FILE>                    Randomly generate a keyfile with the specified file name
    -c, --counter <COUNTER>       1          The counter for when a site password needs to be changed
    -l, --length <LENGTH>         20         The length of the derived site password
    -a, --lowercase                          Include lowercase characters in the derived site password
    -u, --uppercase                          Include uppercase characters in the derived site password
    -n, --numbers                            Include numbers in the derived site password
    -s, --symbols                            Include symbols in the derived site password
    -v, --version                            Prints version information
    -h, --help                               Prints help information
```
