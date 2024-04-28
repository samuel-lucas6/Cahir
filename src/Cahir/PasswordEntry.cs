using static Monocypher.Monocypher;
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
            ConsoleKeyInfo pressedKey;
            do {
                pressedKey = Console.ReadKey(intercept: true);
                if(!char.IsControl(pressedKey.KeyChar)) {
                    if (count > Constants.MaxPasswordChars - 1) {
                        crypto_wipe(new IntPtr(p), password.Length * sizeof(char));
                        throw new ArgumentException($"The password must be at most {Constants.MaxPasswordChars} characters long.");
                    }
                    password[count] = pressedKey.KeyChar;
                    count++;
                }
                else if (pressedKey.Key is ConsoleKey.Backspace or ConsoleKey.Delete && count > 0) {
                    count--;
                    password[count] = '\0';
                }
            } while (pressedKey.Key != ConsoleKey.Enter);
            if (count == 0) {
                throw new ArgumentException("You didn't enter a password.");
            }
            int passwordLength = Encoding.UTF8.GetBytes(password[..count], passwordBuffer);
            crypto_wipe(new IntPtr(p), password.Length * sizeof(char));
            return passwordLength;
        }
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
