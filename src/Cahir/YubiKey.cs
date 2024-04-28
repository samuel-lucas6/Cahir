using Yubico.YubiKey.Otp.Operations;
using static Monocypher.Monocypher;
using System.Security.Cryptography;
using Yubico.Core.Iso7816;
using Yubico.YubiKey.Otp;
using Spectre.Console;
using Yubico.YubiKey;
using System.Text;

namespace Cahir;

public static class YubiKey
{
    public static unsafe void ConfigureSlot()
    {
        IYubiKeyDevice yubiKey = GetYubiKey();
        AnsiConsole.MarkupLine("[darkorange3_1]Warning: This will overwrite the chosen YubiKey OTP slot. Press Ctrl+C to cancel.[/]");
        Console.WriteLine();
        Console.WriteLine("Checking slots...");
        using var session = new OtpSession(yubiKey);
        if (session.IsShortPressConfigured) {
            AnsiConsole.MarkupLine("[darkorange3_1]Slot 1 (Short Touch) is already configured.[/]");
        }
        if (session.IsLongPressConfigured) {
            AnsiConsole.MarkupLine("[darkorange3_1]Slot 2 (Long Touch) is already configured.[/]");
        }
        if (session is { IsShortPressConfigured: false, IsLongPressConfigured: false }) {
            AnsiConsole.MarkupLine("[green3_1]Neither slot is already configured.[/]");
        }
        Console.WriteLine();
        Console.WriteLine("Enter the slot for challenge-response (type 1 or 2):");
        if (!int.TryParse(Console.ReadLine(), out int slot) || (slot != 1 && slot != 2)) {
            throw new ArgumentException("You didn't enter a valid slot.");
        }

        var currentAccessCode = GC.AllocateArray<byte>(SlotAccessCode.MaxAccessCodeLength, pinned: true);
        var newAccessCode = GC.AllocateArray<byte>(SlotAccessCode.MaxAccessCodeLength, pinned: true);
        GetAccessCode(currentAccessCode, currentAccessCode: true);
        GetAccessCode(newAccessCode, currentAccessCode: false);

        var key = GC.AllocateArray<byte>(ConfigureChallengeResponse.HmacSha1KeySize, pinned: true);
        RandomNumberGenerator.Fill(key);
        try {
            session.ConfigureChallengeResponse((Slot)slot).UseHmacSha1().UseKey(key).UseButton()
                .UseCurrentAccessCode(new SlotAccessCode(currentAccessCode))
                .SetNewAccessCode(new SlotAccessCode(newAccessCode)).Execute();
            crypto_wipe(currentAccessCode);
            crypto_wipe(newAccessCode);
            string hexKey = Convert.ToHexString(key);
            fixed (char* h = hexKey) {
                crypto_wipe(key);
                AnsiConsole.MarkupLine("[darkorange3_1]Warning: If you get another YubiKey, use YubiKey Manager to configure a slot with this hex key (press Enter when you're done writing it down):[/]");
                foreach (char c in hexKey) {
                    Console.Write(char.ToLower(c));
                }
                crypto_wipe(new IntPtr(h), hexKey.Length * sizeof(char));
                Console.ReadKey();
                Console.Write($"\r{new string(' ', Console.BufferWidth)}\r");
                Console.WriteLine();
            }
        }
        catch (InvalidOperationException ex) {
            crypto_wipe(key);
            crypto_wipe(currentAccessCode);
            crypto_wipe(newAccessCode);
            throw new ArgumentException("Wrong slot access code.", ex);
        }
    }

    public static void ChallengeResponse(Span<byte> pepper, byte[] challenge)
    {
        try {
            IYubiKeyDevice yubiKey = GetYubiKey();
            using var session = new OtpSession(yubiKey);
            ReadOnlyMemory<byte> response;
            // Try both OTP slots so the user doesn't have to remember the slot
            try {
                // UseYubiOtp(false) means use HMAC-SHA1
                response = session.CalculateChallengeResponse(Slot.LongPress).UseYubiOtp(false).UseChallenge(challenge)
                    .UseTouchNotifier(() => Console.WriteLine("Touch your YubiKey.")).GetDataBytes();
            }
            catch (KeyboardConnectionException) {
                response = session.CalculateChallengeResponse(Slot.ShortPress).UseYubiOtp(false).UseChallenge(challenge)
                    .UseTouchNotifier(() => Console.WriteLine("Touch your YubiKey.")).GetDataBytes();
            }

            // There seems to be no way to pin/wipe the response
            var ctx = new crypto_blake2b_ctx();
            crypto_blake2b_keyed_init(ref ctx, pepper.Length, response.Span);
            crypto_blake2b_update(ref ctx, "cahir.response"u8);
            crypto_blake2b_final(ref ctx, pepper);
        }
        catch (KeyboardConnectionException ex) {
            throw new ArgumentException("No challenge-response YubiKey slot found.", ex);
        }
        catch (MalformedYubiKeyResponseException ex) {
            throw new ArgumentException("You didn't press the YubiKey button.", ex);
        }
        catch (ApduException ex) {
            throw new ArgumentException("The OTP interface is disabled on your YubiKey.", ex);
        }
    }

    private static IYubiKeyDevice GetYubiKey()
    {
        var yubiKeyList = YubiKeyDevice.FindAll().ToList();
        if (yubiKeyList.Count == 0) {
            throw new ArgumentException("No YubiKey found.");
        }
        if (yubiKeyList.Count > 1) {
            throw new ArgumentException("Multiple YubiKeys detected.");
        }
        return yubiKeyList.First();
    }

    private static unsafe void GetAccessCode(Span<byte> accessCode, bool currentAccessCode)
    {
        Console.WriteLine(currentAccessCode ? "Enter your 6-digit slot access code (leave blank if there isn't one):" : "Enter a new 6-digit slot access code (leave blank for no protection):");
        int count = 0;
        Span<char> code = stackalloc char[SlotAccessCode.MaxAccessCodeLength];
        code.Clear();
        fixed (char* c = code) {
            ConsoleKeyInfo pressedKey;
            do {
                pressedKey = Console.ReadKey(intercept: true);
                if(!char.IsControl(pressedKey.KeyChar)) {
                    if (count > SlotAccessCode.MaxAccessCodeLength - 1) {
                        crypto_wipe(new IntPtr(c), code.Length * sizeof(char));
                        throw new ArgumentException($"The slot access code must be at most {SlotAccessCode.MaxAccessCodeLength} characters long.");
                    }
                    code[count] = pressedKey.KeyChar;
                    count++;
                }
                else if (pressedKey.Key is ConsoleKey.Backspace or ConsoleKey.Delete && count > 0) {
                    count--;
                    code[count] = '\0';
                }
            } while (pressedKey.Key != ConsoleKey.Enter);
            try {
                Encoding.UTF8.GetBytes(code, accessCode);
            }
            catch (ArgumentException ex) {
                crypto_wipe(accessCode);
                throw new ArgumentException($"The UTF-8 encoded slot access code is greater than {SlotAccessCode.MaxAccessCodeLength} bytes long.", ex);
            }
            finally {
                crypto_wipe(new IntPtr(c), code.Length * sizeof(char));
            }
            Console.WriteLine();
        }
    }
}
