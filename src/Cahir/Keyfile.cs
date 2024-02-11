using static Monocypher.Monocypher;
using System.Security.Cryptography;

namespace Cahir;

public static class Keyfile
{
    public static void ReadKeyfile(Span<byte> pepper, string path)
    {
        try {
            using var fileStream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            int bytesRead;
            Span<byte> buffer = GC.AllocateArray<byte>(4096, pinned: true);
            var ctx = new crypto_blake2b_ctx();
            crypto_blake2b_init(ref ctx, pepper.Length);
            while ((bytesRead = fileStream.Read(buffer)) > 0) {
                crypto_blake2b_update(ref ctx, buffer[..bytesRead]);
            }
            crypto_blake2b_final(ref ctx, pepper);
            crypto_wipe(buffer);
        }
        catch (Exception ex) {
            throw new IOException("Unable to read the keyfile.", ex);
        }
    }

    public static void GenerateKeyfile(string path)
    {
        try {
            Span<byte> pepper = stackalloc byte[Constants.KeySize];
            RandomNumberGenerator.Fill(pepper);
            using var fileStream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            fileStream.Write(pepper);
            crypto_wipe(pepper);
            File.SetAttributes(path, FileAttributes.ReadOnly);
        }
        catch (Exception ex) {
            throw new IOException("Unable to generate a random keyfile.", ex);
        }
    }
}
