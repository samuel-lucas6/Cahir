namespace Cahir;

public static class Constants
{
    public const int MaxPasswordChars = 128;
    public const int DefaultCounter = 1;
    public const int DefaultLength = 20;
    public const int MaxLength = 128;
    public const int KeySize = 32;
    public const int FingerprintSize = 64;
    public const int SaltSize = 32;
    public const int CRYPTO_ARGON2_ID = 2;
    public const int Argon2MemorySize = 536870912; // 512 MiB
    public const int Argon2BlockSize = 1024;
    public const int Argon2Passes = 3;
    public const int Argon2Lanes = 1;
    public const int UInt128Size = 16;
}
