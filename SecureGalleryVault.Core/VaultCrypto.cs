using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace SecureGalleryVault.Core;

public static class VaultCrypto
{
    private const int NonceLength = 12;
    private const int TagLength = 16;

    public static (VaultConfig Config, byte[] MasterKey) CreateVaultConfig(string passcode)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var masterKey = RandomNumberGenerator.GetBytes(32);
        var pinKey = DerivePasscodeKey(passcode, salt);
        var packet = EncryptBytes(masterKey, pinKey);

        return (new VaultConfig
        {
            SaltBase64 = Convert.ToBase64String(salt),
            MasterKeyPacketBase64 = Convert.ToBase64String(packet),
            CreatedUtc = DateTimeOffset.UtcNow
        }, masterKey);
    }

    public static byte[] UnlockMasterKey(VaultConfig config, string passcode)
    {
        var salt = Convert.FromBase64String(config.SaltBase64);
        var pinKey = DerivePasscodeKey(passcode, salt);
        var packet = Convert.FromBase64String(config.MasterKeyPacketBase64);
        return DecryptBytes(packet, pinKey);
    }

    public static byte[] EncryptBytes(byte[] plaintext, byte[] key)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceLength);
        var cipher = new byte[plaintext.Length];
        var tag = new byte[TagLength];

        using var aes = new AesGcm(key, TagLength);
        aes.Encrypt(nonce, plaintext, cipher, tag);

        var packet = new byte[sizeof(int) + NonceLength + TagLength + cipher.Length];
        BinaryPrimitives.WriteInt32LittleEndian(packet.AsSpan(0, sizeof(int)), plaintext.Length);
        nonce.CopyTo(packet, sizeof(int));
        tag.CopyTo(packet, sizeof(int) + NonceLength);
        cipher.CopyTo(packet, sizeof(int) + NonceLength + TagLength);
        return packet;
    }

    public static byte[] DecryptBytes(byte[] packet, byte[] key)
    {
        if (packet.Length < sizeof(int) + NonceLength + TagLength)
        {
            throw new CryptographicException("Encrypted packet is too short.");
        }

        var declaredLength = BinaryPrimitives.ReadInt32LittleEndian(packet.AsSpan(0, sizeof(int)));
        var nonce = packet.AsSpan(sizeof(int), NonceLength);
        var tag = packet.AsSpan(sizeof(int) + NonceLength, TagLength);
        var cipher = packet.AsSpan(sizeof(int) + NonceLength + TagLength);
        var plaintext = new byte[declaredLength];

        using var aes = new AesGcm(key, TagLength);
        aes.Decrypt(nonce, cipher, tag, plaintext);
        return plaintext;
    }

    public static byte[] DeriveSessionKey(
        byte[] sharedSecret,
        byte[] clientNonce,
        byte[] serverNonce,
        string sessionCode)
    {
        var salt = clientNonce.Concat(serverNonce).ToArray();
        var info = Encoding.UTF8.GetBytes($"SecureGalleryVault|{sessionCode}");
        return HkdfSha256(sharedSecret, salt, info, 32);
    }

    public static string CreateSessionCode()
    {
        var value = RandomNumberGenerator.GetInt32(100000, 999999);
        return value.ToString();
    }

    public static void Zero(byte[]? buffer)
    {
        if (buffer is not null)
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private static byte[] DerivePasscodeKey(string passcode, byte[] salt)
    {
        return Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(passcode),
            salt,
            VaultConstants.Pbkdf2Iterations,
            HashAlgorithmName.SHA256,
            32);
    }

    private static byte[] HkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length)
    {
        using var hmac = new HMACSHA256(salt);
        var prk = hmac.ComputeHash(ikm);

        var output = new byte[length];
        var block = Array.Empty<byte>();
        var offset = 0;
        byte counter = 1;

        while (offset < length)
        {
            using var expand = new HMACSHA256(prk);
            var input = new byte[block.Length + info.Length + 1];
            block.CopyTo(input, 0);
            info.CopyTo(input, block.Length);
            input[^1] = counter++;
            block = expand.ComputeHash(input);

            var toCopy = Math.Min(block.Length, length - offset);
            Buffer.BlockCopy(block, 0, output, offset, toCopy);
            offset += toCopy;
        }

        Zero(prk);
        return output;
    }
}
