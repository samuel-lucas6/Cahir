using static Monocypher.Monocypher;
using System.Buffers.Binary;
using System.ComponentModel;
using Spectre.Console.Cli;
using Spectre.Console;
using System.Text;

namespace Cahir;

public static class Program
{
    public static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        var app = new CommandApp<CahirCommand>();
        app.Configure(config =>
        {
            config.AddExample("-i \"alicejones@pm.me\" -d \"https://github.com\"");
            config.AddExample("-i \"alicejones@pm.me\" -d \"https://github.com\" -p \"correct horse battery staple\"");
            config.AddExample("-i \"+44 07488 855302\" -d \"https://github.com\" -f \"password.txt\"");
            config.AddExample("-i \"+44 07488 855302\" -d \"https://github.com\" -k \"pepper.key\"");
        });
        return app.Run(args);
    }
}

internal sealed class CahirCommand : Command<CahirCommand.Settings>
{
    public sealed class Settings : CommandSettings
    {
        [CommandOption("-i|--identity <IDENTITY>")]
        [Description("Your unique identifier (e.g. email address)")]
        public string? Identity { get; set; }

        [CommandOption("-d|--domain <DOMAIN>")]
        [Description("The website URL (e.g. https://github.com)")]
        public string? Domain { get; set; }

        [CommandOption("-p|--password <PASSWORD>")]
        [Description("Your master password (omit for interactive entry)")]
        public string? Password { get; set; }

        [CommandOption("-f|--password-file <FILE>")]
        [Description("Your master password stored as a file (omit for interactive entry)")]
        public string? PasswordFile { get; set; }

        [CommandOption("-k|--keyfile <FILE>")]
        [Description("Your pepper stored as a file")]
        public string? Keyfile { get; set; }

        [CommandOption("-g|--generate <FILE>")]
        [Description("Randomly generate a keyfile with the specified file name")]
        public string? Generate { get; set; }

        [CommandOption("-c|--counter <COUNTER>")]
        [Description("The counter for when a site password needs to be changed")]
        public int Counter { get; set; } = Constants.DefaultCounter;

        [CommandOption("-l|--length <LENGTH>")]
        [Description("The length of the derived site password")]
        public int? Length { get; set; }

        [CommandOption("-a|--lowercase")]
        [Description("Include lowercase characters in the derived site password")]
        public bool Lowercase { get; set; }

        [CommandOption("-u|--uppercase")]
        [Description("Include uppercase characters in the derived site password")]
        public bool Uppercase { get; set; }

        [CommandOption("-n|--numbers")]
        [Description("Include numbers in the derived site password")]
        public bool Numbers { get; set; }

        [CommandOption("-s|--symbols")]
        [Description("Include symbols in the derived site password")]
        public bool Symbols { get; set; }

        [CommandOption("-w|--words")]
        [Description("Derive a passphrase")]
        public bool Words { get; set; }
    }

    public override ValidationResult Validate(CommandContext context, Settings settings)
    {
        if (settings.Generate != null) {
            if (Directory.Exists(settings.Generate) || settings.Generate.EndsWith(Path.DirectorySeparatorChar) || settings.Generate.EndsWith(Path.AltDirectorySeparatorChar) || settings.Generate.EndsWith(Path.VolumeSeparatorChar)) {
                return ValidationResult.Error("-g|--generate <FILE> must specify the name of a file.");
            }
            if (File.Exists(settings.Generate)) {
                return ValidationResult.Error("-g|--generate <FILE> must specify a file that doesn't exist.");
            }
            var invalidChars = Path.GetInvalidFileNameChars();
            if (settings.Generate.Any(c => invalidChars.Contains(c))) {
                return ValidationResult.Error("-g|--generate <FILE> must specify a valid file name.");
            }
            if (settings.Identity != null || settings.Domain != null || settings.Password != null || settings.PasswordFile != null ||
                settings.Keyfile != null || settings.Counter != Constants.DefaultCounter || settings.Length != Constants.DefaultLength ||
                settings.Lowercase || settings.Uppercase || settings.Numbers || settings.Symbols || settings.Words) {
                return ValidationResult.Error("-g|--generate <FILE> must be specified without other options.");
            }
            return ValidationResult.Success();
        }
        if (string.IsNullOrWhiteSpace(settings.Identity)) {
            return ValidationResult.Error("-i|--identity <IDENTITY> must be specified.");
        }
        if (string.IsNullOrWhiteSpace(settings.Domain)) {
            return ValidationResult.Error("-d|--domain <DOMAIN> must be specified.");
        }
        if (!Uri.IsWellFormedUriString(settings.Domain, UriKind.Absolute)) {
            return ValidationResult.Error("-d|--domain <DOMAIN> must be a proper URL.");
        }
        if (settings.Password is { Length: > Constants.MaxPasswordChars }) {
            return ValidationResult.Error($"The password must be at most {Constants.MaxPasswordChars} characters long.");
        }
        if (settings.PasswordFile != null) {
            if (settings.Password != null) {
                return ValidationResult.Error("-f|--password-file <FILE> cannot be specified at the same time as -p|--password <PASSWORD>.");
            }
            if (!File.Exists(settings.PasswordFile)) {
                return ValidationResult.Error("The password file doesn't exist.");
            }
            try {
                var fileLength = new FileInfo(settings.PasswordFile).Length;
                if (fileLength == 0) {
                    return ValidationResult.Error("The password file cannot be empty.");
                }
                if (fileLength > Encoding.UTF8.GetMaxByteCount(Constants.MaxPasswordChars)) {
                    return ValidationResult.Error("The password file is too long.");
                }
            }
            catch (Exception) {
                return ValidationResult.Error("Unable to access the password file.");
            }
        }
        if (settings.Keyfile != null) {
            if (!File.Exists(settings.Keyfile)) {
                return ValidationResult.Error("The keyfile doesn't exist.");
            }
            try {
                if (new FileInfo(settings.Keyfile).Length == 0) {
                    return ValidationResult.Error("The keyfile cannot be empty.");
                }
            }
            catch (Exception) {
                return ValidationResult.Error("Unable to access the keyfile.");
            }
        }
        if (settings.Counter <= 0) {
            return ValidationResult.Error("-c|--counter <COUNTER> must be greater than 0.");
        }
        if (settings is { Words: false, Length: null }) {
            settings.Length = Constants.DefaultLength;
        }
        if (settings is { Words: true, Length: null }) {
            settings.Length = Constants.DefaultWords;
        }
        if (settings is { Words: false, Length: <= 0 or > Constants.MaxLength }) {
            return ValidationResult.Error($"-l|--length <LENGTH> must be greater than 0 and at most {Constants.MaxLength} for a password.");
        }
        if (settings is { Words: true, Length: <= 0 or > Constants.MaxWords }) {
            return ValidationResult.Error($"-l|--length <LENGTH> must be greater than 0 and at most {Constants.MaxWords} for a passphrase.");
        }
        if (settings is { Words: true, Lowercase: true }) {
            return ValidationResult.Error("-a|--lowercase cannot be used with -w|--words.");
        }
        if (settings is { Words: false, Lowercase: false, Uppercase: false, Numbers: false, Symbols: false }) {
            settings.Lowercase = true;
            settings.Uppercase = true;
            settings.Numbers = true;
            settings.Symbols = true;
        }
        return ValidationResult.Success();
    }

    // Spectre.Console catches exceptions and displays their message as an error
    public override unsafe int Execute(CommandContext context, Settings settings)
    {
        if (settings.Generate != null) {
            Keyfile.GenerateKeyfile(settings.Generate);
            AnsiConsole.MarkupLine("[green3_1]Keyfile generated successfully.[/]");
            return Environment.ExitCode;
        }

        Span<byte> masterKey = stackalloc byte[Constants.KeySize], siteKey = stackalloc byte[Constants.KeySize];
        Span<byte> identity = Encoding.UTF8.GetBytes(settings.Identity!);
        Span<byte> domain = Encoding.UTF8.GetBytes(new Uri(settings.Domain!).Host);
        Span<byte> passwordBuffer = GC.AllocateArray<byte>(Encoding.UTF8.GetMaxByteCount(settings.Password?.Length ?? Constants.MaxPasswordChars), pinned: true);
        int passwordLength;
        if (settings.PasswordFile != null) {
            passwordLength = PasswordEntry.ReadPasswordFile(passwordBuffer, settings.PasswordFile);
        }
        else if (settings.Password != null) {
            passwordLength = Encoding.UTF8.GetBytes(settings.Password, passwordBuffer);
            // Supposedly might crash the runtime but is fine based on my testing
            fixed (char* p = settings.Password) {
                // sizeof(char) because .NET uses UTF-16 encoding
                crypto_wipe(new IntPtr(p), settings.Password.Length * sizeof(char));
            }
        }
        else {
            passwordLength = PasswordEntry.GetPassword(passwordBuffer);
        }
        Span<byte> password = passwordBuffer[..passwordLength];
        Span<byte> length = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32LittleEndian(length, (uint)settings.Length!.Value);
        Span<byte> characterSet = stackalloc byte[5];
        characterSet[0] = (byte)(settings.Lowercase ? 0x01 : 0x00);
        characterSet[1] = (byte)(settings.Uppercase ? 0x01 : 0x00);
        characterSet[2] = (byte)(settings.Numbers ? 0x01 : 0x00);
        characterSet[3] = (byte)(settings.Symbols ? 0x01 : 0x00);
        characterSet[4] = (byte)(settings.Words ? 0x01 : 0x00);
        Span<byte> counter = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32LittleEndian(counter, (uint)settings.Counter);
        Span<byte> pepper = stackalloc byte[Constants.KeySize];
        if (settings.Keyfile != null) {
            Keyfile.ReadKeyfile(pepper, settings.Keyfile);
        }

        AnsiConsole.MarkupLine("[darkorange3_1]Deriving keys from master password...[/]");
        Generator.DeriveMasterKey(masterKey, identity, password, settings.Keyfile != null ? pepper : ReadOnlySpan<byte>.Empty);
        crypto_wipe(password);
        crypto_wipe(pepper);

        Generator.DeriveSiteKey(siteKey, masterKey, domain, counter, length, characterSet);
        crypto_wipe(masterKey);

        // + settings.Length.Value for the word separator chars and a number
        Span<char> sitePassword = stackalloc char[!settings.Words ? settings.Length.Value : (settings.Length.Value * Constants.LongestWordLength) + settings.Length.Value];
        fixed (char* s = sitePassword) {
            if (!settings.Words) {
                Generator.DeriveSitePassword(sitePassword, siteKey, settings.Lowercase, settings.Uppercase, settings.Numbers, settings.Symbols);
            }
            else {
                Generator.DeriveSitePassphrase(sitePassword, siteKey, settings.Length.Value, settings.Uppercase, settings.Numbers, settings.Symbols);
            }
            crypto_wipe(siteKey);
            Console.WriteLine();
            AnsiConsole.MarkupLine("[green3_1]-----BEGIN SITE PASSWORD-----[/]");
            foreach (char c in sitePassword) {
                Console.Write(c);
            }
            Console.WriteLine();
            AnsiConsole.MarkupLine("[green3_1]-----END SITE PASSWORD-----[/]");
            crypto_wipe(new IntPtr(s), sitePassword.Length * sizeof(char));
        }
        return Environment.ExitCode;
    }
}
