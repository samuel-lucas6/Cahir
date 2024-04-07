using static Monocypher.Monocypher;
using System.Buffers.Binary;

namespace Cahir;

public static class Generator
{
    public static unsafe void DeriveMasterKey(Span<byte> masterKey, ReadOnlySpan<byte> identity, ReadOnlySpan<byte> password)
    {
        Span<byte> salt = stackalloc byte[Constants.SaltSize];
        var ctx = new crypto_blake2b_ctx();
        crypto_blake2b_init(ref ctx, salt.Length);
        crypto_blake2b_update(ref ctx, "cahir.masterkey"u8);
        crypto_blake2b_update(ref ctx, identity);
        crypto_blake2b_final(ref ctx, salt);

        Span<byte> workArea = new byte[Constants.Argon2MemorySize];
        fixed (byte* p = password, s = salt) {
            var config = new crypto_argon2_config
            {
                algorithm = Constants.CRYPTO_ARGON2_ID,
                nb_blocks = (uint)(workArea.Length / Constants.Argon2BlockSize),
                nb_passes = Constants.Argon2Passes,
                nb_lanes = Constants.Argon2Lanes
            };
            var inputs = new crypto_argon2_inputs
            {
                pass = new IntPtr(p),
                salt = new IntPtr(s),
                pass_size = (uint)password.Length,
                salt_size = (uint)salt.Length
            };
            var extras = new crypto_argon2_extras
            {
                key = IntPtr.Zero,
                key_size = 0,
                ad = IntPtr.Zero,
                ad_size = 0
            };
            crypto_argon2(masterKey, workArea, config, inputs, extras);
        }
    }

    public static void DeriveChallenge(Span<byte> challenge, ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> domain, ReadOnlySpan<byte> counter, ReadOnlySpan<byte> length, ReadOnlySpan<byte> characterSet)
    {
        var ctx = new crypto_blake2b_ctx();
        crypto_blake2b_keyed_init(ref ctx, challenge.Length, masterKey);
        crypto_blake2b_update(ref ctx, "cahir.challenge"u8);
        crypto_blake2b_update(ref ctx, counter);
        crypto_blake2b_update(ref ctx, length);
        crypto_blake2b_update(ref ctx, characterSet);
        crypto_blake2b_update(ref ctx, domain);
        crypto_blake2b_final(ref ctx, challenge);
    }

    public static void DeriveSiteKey(Span<byte> siteKey, ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> domain, ReadOnlySpan<byte> counter, ReadOnlySpan<byte> length, ReadOnlySpan<byte> characterSet)
    {
        var ctx = new crypto_blake2b_ctx();
        crypto_blake2b_keyed_init(ref ctx, siteKey.Length, masterKey);
        crypto_blake2b_update(ref ctx, "cahir.sitekey"u8);
        crypto_blake2b_update(ref ctx, counter);
        crypto_blake2b_update(ref ctx, length);
        crypto_blake2b_update(ref ctx, characterSet);
        crypto_blake2b_update(ref ctx, domain);
        crypto_blake2b_final(ref ctx, siteKey);
    }

    public static void DeriveSitePassword(Span<char> sitePassword, ReadOnlySpan<byte> siteKey, bool lowercase, bool uppercase, bool numbers, bool symbols)
    {
        Span<byte> ciphertext = stackalloc byte[sitePassword.Length * Constants.UInt128Size];
        ciphertext.Clear();
        ReadOnlySpan<byte> nonce = "cahir.sitepw"u8;
        crypto_chacha20_ietf(ciphertext, ciphertext, siteKey, nonce, ctr: 0);
        var characterSet = new List<char>();
        if (lowercase) { characterSet.AddRange("abcdefghijklmnopqrstuvwxyz"); }
        if (uppercase) { characterSet.AddRange("ABCDEFGHIJKLMNOPQRSTUVWXYZ"); }
        if (numbers) { characterSet.AddRange("0123456789"); }
        if (symbols) { characterSet.AddRange("!#$%&'()*+,-./:;<=>?@[]^_`{}~"); }
        for (int i = 0; i < sitePassword.Length; i++) {
            var randomIndex = BinaryPrimitives.ReadUInt128LittleEndian(ciphertext.Slice(i * Constants.UInt128Size, Constants.UInt128Size)) % (UInt128)characterSet.Count;
            sitePassword[i] = characterSet[(int)randomIndex];
        }
        crypto_wipe(ciphertext);
    }

    public static void DeriveSitePassphrase(Span<char> sitePassphrase, ReadOnlySpan<byte> siteKey, int wordCount, bool capitalise, bool number, bool symbol)
    {
        // If number == true, randomly generate a number and position
        int offset = number ? 2 : 0;
        Span<byte> ciphertext = stackalloc byte[(wordCount + offset) * Constants.UInt128Size];
        ciphertext.Clear();
        ReadOnlySpan<byte> nonce = "cahir.sitepw"u8;
        crypto_chacha20_ietf(ciphertext, ciphertext, siteKey, nonce, ctr: 0);

        ReadOnlySpan<char> characterSet = "0123456789";
        UInt128 randomNumber = 0, randomPosition = 0;
        if (number) {
            randomNumber = BinaryPrimitives.ReadUInt128LittleEndian(ciphertext[..Constants.UInt128Size]) % (UInt128)characterSet.Length;
            randomPosition = BinaryPrimitives.ReadUInt128LittleEndian(ciphertext.Slice(Constants.UInt128Size, Constants.UInt128Size)) % (UInt128)wordCount;
        }

        int count = 0;
        string[] wordlist = Resources.wordlist.Split(separator: ["\n"], StringSplitOptions.RemoveEmptyEntries);
        for (int i = 0; i < wordCount; i++) {
            var randomIndex = BinaryPrimitives.ReadUInt128LittleEndian(ciphertext.Slice((i + offset) * Constants.UInt128Size, Constants.UInt128Size)) % (UInt128)wordlist.Length;
            ReadOnlySpan<char> word = wordlist[(int)randomIndex].AsSpan();
            for (int j = 0; j < word.Length; j++) {
                sitePassphrase[count] = capitalise && j == 0 ? char.ToUpper(word[j]) : word[j];
                count++;
            }
            if (number && i == (int)randomPosition) {
                sitePassphrase[count] = characterSet[(int)randomNumber];
                count++;
            }
            if (i != wordCount - 1) {
                sitePassphrase[count] = symbol ? '-' : ' ';
                count++;
            }
        }
        crypto_wipe(ciphertext);
    }
}
