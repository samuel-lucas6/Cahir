using System.Text;

namespace Cahir;

public static class Constants
{
    public static readonly int MaxPasswordBytes = Encoding.UTF8.GetMaxByteCount(MaxPasswordChars);
    public const int MaxPasswordChars = 128;
    public const int DefaultCounter = 1;
    public const int DefaultLength = 20;
    public const int DefaultWords = 8;
    public const int MaxLength = 128;
    public const int MaxWords = 12;
    public const int DefaultSlot = 2;
    public const int LongestWordLength = 8;
    public const int KeySize = 32;
    public const int SaltSize = 32;
    public const int CRYPTO_ARGON2_ID = 2;
    public const int Argon2MemorySize = 268435456; // 256 MiB
    public const int Argon2BlockSize = 1024;
    public const int Argon2Passes = 3;
    public const int Argon2Lanes = 1;
    public const int UInt128Size = 16;
}
