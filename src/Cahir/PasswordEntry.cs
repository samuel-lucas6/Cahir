using static Monocypher.Monocypher;
using System.Buffers.Binary;
using System.Text;

namespace Cahir;

public static class PasswordEntry
{
    public static unsafe int GetPassword(Span<byte> passwordBuffer)
    {
        Console.WriteLine("Enter your master password:");
        int count = 0;
        Span<char> password = stackalloc char[Constants.MaxPasswordChars];
        fixed (char* p = password) {
            string[] wordlist = Resources.wordlist.Split(separator: ["\n"], StringSplitOptions.RemoveEmptyEntries);
            ConsoleKeyInfo pressedKey;
            do {
                pressedKey = Console.ReadKey(intercept: true);
                if (count >= Constants.MaxPasswordChars) {
                    Console.Write($"\r{new string(' ', Console.BufferWidth)}\r");
                    throw new ArgumentException($"The password must be at most {Constants.MaxPasswordChars} characters long.");
                }
                if(!char.IsControl(pressedKey.KeyChar)) {
                    password[count] = pressedKey.KeyChar;
                    count++;
                }
                else if (pressedKey.Key is ConsoleKey.Backspace or ConsoleKey.Delete && count > 0) {
                    count--;
                    password[count] = '\0';
                }
                Fingerprint(passwordBuffer, password[..count], wordlist);
            } while (pressedKey.Key != ConsoleKey.Enter);
            crypto_wipe(passwordBuffer);
            Console.Write($"\r{new string(' ', Console.BufferWidth)}\r");
            if (count == 0) {
                throw new ArgumentException("You didn't enter a password.");
            }
            int passwordLength = Encoding.UTF8.GetBytes(password[..count], passwordBuffer);
            crypto_wipe(new IntPtr(p), password.Length * sizeof(char));
            return passwordLength;
        }
    }

    private static void Fingerprint(Span<byte> passwordBuffer, ReadOnlySpan<char> typedPassword, IReadOnlyList<string> wordlist)
    {
        int passwordLength = Encoding.UTF8.GetBytes(typedPassword, passwordBuffer);
        Span<byte> fingerprint = stackalloc byte[Constants.FingerprintSize];
        var ctx = new crypto_blake2b_ctx();
        crypto_blake2b_init(ref ctx, fingerprint.Length);
        crypto_blake2b_update(ref ctx, "cahir.fingerprint"u8);
        crypto_blake2b_update(ref ctx, passwordBuffer[..passwordLength]);
        crypto_blake2b_final(ref ctx, fingerprint);

        var index0 = BinaryPrimitives.ReadUInt128LittleEndian(fingerprint[..16]) % (UInt128)wordlist.Count;
        var index1 = BinaryPrimitives.ReadUInt128LittleEndian(fingerprint[16..32]) % (UInt128)wordlist.Count;
        var index2 = BinaryPrimitives.ReadUInt128LittleEndian(fingerprint[32..48]) % (UInt128)wordlist.Count;
        var index3 = BinaryPrimitives.ReadUInt128LittleEndian(fingerprint[48..]) % (UInt128)wordlist.Count;
        Console.Write($"\r{new string(' ', Console.BufferWidth)}\r");
        Console.Write($"{wordlist[(int)index0]}-{wordlist[(int)index1]}-{wordlist[(int)index2]}-{wordlist[(int)index3]}".Replace("\r", ""));
        crypto_wipe(fingerprint);
    }

    public static int ReadPasswordFile(Span<byte> passwordBuffer, string path)
    {
        try {
            using var fileStream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            return fileStream.Read(passwordBuffer);
        }
        catch (Exception ex) {
            throw new IOException("Unable to read the password file.", ex);
        }
    }
}
