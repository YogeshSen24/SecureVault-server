using System.Buffers.Binary;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SecureGalleryVault.Core;

public sealed class SecureChannel : IAsyncDisposable
{
    private static readonly JsonSerializerOptions SerializerOptions = new(JsonSerializerDefaults.Web);

    private readonly Stream _stream;
    private readonly byte[] _sessionKey;

    private SecureChannel(Stream stream, byte[] sessionKey)
    {
        _stream = stream;
        _sessionKey = sessionKey;
    }

    public static async Task<SecureChannel> OpenClientAsync(
        Stream stream,
        string sessionCode,
        string deviceName,
        CancellationToken cancellationToken = default)
    {
        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var clientNonce = RandomNumberGenerator.GetBytes(16);
        var hello = new HelloPacket
        {
            Role = "viewer",
            DeviceName = deviceName,
            NonceBase64 = Convert.ToBase64String(clientNonce),
            PublicKeyBase64 = Convert.ToBase64String(ecdh.ExportSubjectPublicKeyInfo())
        };

        await WriteLineAsync(stream, JsonSerializer.Serialize(hello, SerializerOptions), cancellationToken);
        var responseLine = await ReadLineAsync(stream, cancellationToken);
        var serverHello = JsonSerializer.Deserialize<HelloPacket>(responseLine, SerializerOptions)
            ?? throw new InvalidOperationException("Server handshake was invalid.");

        var sessionKey = BuildSessionKey(
            ecdh,
            Convert.FromBase64String(serverHello.PublicKeyBase64),
            clientNonce,
            Convert.FromBase64String(serverHello.NonceBase64),
            sessionCode);

        var channel = new SecureChannel(stream, sessionKey);
        await channel.SendAsync(new EnvelopeMessage
        {
            Type = "auth",
            Message = deviceName
        }, cancellationToken);

        var authResponse = await channel.ReceiveAsync(cancellationToken);
        if (!string.Equals(authResponse.Type, "auth-ok", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(authResponse.Message ?? "Authentication failed.");
        }

        return channel;
    }

    public static async Task<SecureChannel> OpenServerAsync(
        Stream stream,
        string sessionCode,
        CancellationToken cancellationToken = default)
    {
        var line = await ReadLineAsync(stream, cancellationToken);
        var clientHello = JsonSerializer.Deserialize<HelloPacket>(line, SerializerOptions)
            ?? throw new InvalidOperationException("Client handshake was invalid.");

        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var serverNonce = RandomNumberGenerator.GetBytes(16);
        var response = new HelloPacket
        {
            Role = "vault",
            DeviceName = Environment.MachineName,
            NonceBase64 = Convert.ToBase64String(serverNonce),
            PublicKeyBase64 = Convert.ToBase64String(ecdh.ExportSubjectPublicKeyInfo())
        };

        await WriteLineAsync(stream, JsonSerializer.Serialize(response, SerializerOptions), cancellationToken);
        var sessionKey = BuildSessionKey(
            ecdh,
            Convert.FromBase64String(clientHello.PublicKeyBase64),
            Convert.FromBase64String(clientHello.NonceBase64),
            serverNonce,
            sessionCode);

        var channel = new SecureChannel(stream, sessionKey);
        var authMessage = await channel.ReceiveAsync(cancellationToken);
        if (!string.Equals(authMessage.Type, "auth", StringComparison.Ordinal))
        {
            throw new InvalidOperationException("Client did not complete secure authentication.");
        }

        await channel.SendAsync(new EnvelopeMessage
        {
            Type = "auth-ok",
            Message = "ready"
        }, cancellationToken);
        return channel;
    }

    public static async Task<(SecureChannel Channel, string MatchedSessionCode)> OpenServerWithCandidatesAsync(
        Stream stream,
        IReadOnlyCollection<string> sessionCodes,
        CancellationToken cancellationToken = default)
    {
        var line = await ReadLineAsync(stream, cancellationToken);
        var clientHello = JsonSerializer.Deserialize<HelloPacket>(line, SerializerOptions)
            ?? throw new InvalidOperationException("Client handshake was invalid.");

        using var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var serverNonce = RandomNumberGenerator.GetBytes(16);
        var response = new HelloPacket
        {
            Role = "vault",
            DeviceName = Environment.MachineName,
            NonceBase64 = Convert.ToBase64String(serverNonce),
            PublicKeyBase64 = Convert.ToBase64String(ecdh.ExportSubjectPublicKeyInfo())
        };

        await WriteLineAsync(stream, JsonSerializer.Serialize(response, SerializerOptions), cancellationToken);

        var lengthPrefix = await ReadExactAsync(stream, sizeof(int), cancellationToken);
        var packetLength = BinaryPrimitives.ReadInt32LittleEndian(lengthPrefix);
        if (packetLength <= 0 || packetLength > 128 * 1024 * 1024)
        {
            throw new InvalidOperationException("Encrypted message length was invalid.");
        }

        var encrypted = await ReadExactAsync(stream, packetLength, cancellationToken);
        foreach (var sessionCode in sessionCodes.Where(code => !string.IsNullOrWhiteSpace(code)).Distinct(StringComparer.Ordinal))
        {
            var sessionKey = BuildSessionKey(
                ecdh,
                Convert.FromBase64String(clientHello.PublicKeyBase64),
                Convert.FromBase64String(clientHello.NonceBase64),
                serverNonce,
                sessionCode);

            try
            {
                var authMessage = DecryptMessage(encrypted, sessionKey);
                if (!string.Equals(authMessage.Type, "auth", StringComparison.Ordinal))
                {
                    throw new InvalidOperationException("Client did not complete secure authentication.");
                }

                var channel = new SecureChannel(stream, sessionKey);
                await channel.SendAsync(new EnvelopeMessage
                {
                    Type = "auth-ok",
                    Message = "ready"
                }, cancellationToken);
                return (channel, sessionCode);
            }
            catch
            {
                VaultCrypto.Zero(sessionKey);
            }
        }

        throw new InvalidOperationException("Client did not complete secure authentication.");
    }

    public async Task SendAsync(EnvelopeMessage message, CancellationToken cancellationToken = default)
    {
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(message, SerializerOptions);
        var encrypted = VaultCrypto.EncryptBytes(plaintext, _sessionKey);
        var lengthPrefix = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(lengthPrefix, encrypted.Length);

        await _stream.WriteAsync(lengthPrefix, cancellationToken);
        await _stream.WriteAsync(encrypted, cancellationToken);
        await _stream.FlushAsync(cancellationToken);
    }

    public async Task<EnvelopeMessage> ReceiveAsync(CancellationToken cancellationToken = default)
    {
        var lengthPrefix = await ReadExactAsync(sizeof(int), cancellationToken);
        var packetLength = BinaryPrimitives.ReadInt32LittleEndian(lengthPrefix);
        if (packetLength <= 0 || packetLength > 128 * 1024 * 1024)
        {
            throw new InvalidOperationException("Encrypted message length was invalid.");
        }

        var encrypted = await ReadExactAsync(packetLength, cancellationToken);
        var plaintext = VaultCrypto.DecryptBytes(encrypted, _sessionKey);
        return JsonSerializer.Deserialize<EnvelopeMessage>(plaintext, SerializerOptions)
            ?? throw new InvalidOperationException("Secure message could not be parsed.");
    }

    public ValueTask DisposeAsync()
    {
        VaultCrypto.Zero(_sessionKey);
        _stream.Dispose();
        return ValueTask.CompletedTask;
    }

    private async Task<byte[]> ReadExactAsync(int length, CancellationToken cancellationToken)
    {
        var buffer = new byte[length];
        var offset = 0;
        while (offset < length)
        {
            var read = await _stream.ReadAsync(buffer.AsMemory(offset, length - offset), cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException("The secure channel closed unexpectedly.");
            }

            offset += read;
        }

        return buffer;
    }

    private static async Task<byte[]> ReadExactAsync(Stream stream, int length, CancellationToken cancellationToken)
    {
        var buffer = new byte[length];
        var offset = 0;
        while (offset < length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(offset, length - offset), cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException("The secure channel closed unexpectedly.");
            }

            offset += read;
        }

        return buffer;
    }

    private static byte[] BuildSessionKey(
        ECDiffieHellman localKey,
        byte[] remotePublicKey,
        byte[] clientNonce,
        byte[] serverNonce,
        string sessionCode)
    {
        using var remote = ECDiffieHellman.Create();
        remote.ImportSubjectPublicKeyInfo(remotePublicKey, out _);
        var sharedSecret = localKey.DeriveKeyMaterial(remote.PublicKey);
        var sessionKey = VaultCrypto.DeriveSessionKey(sharedSecret, clientNonce, serverNonce, sessionCode);
        VaultCrypto.Zero(sharedSecret);
        return sessionKey;
    }

    private static async Task<string> ReadLineAsync(Stream stream, CancellationToken cancellationToken)
    {
        using var buffer = new MemoryStream();
        var oneByte = new byte[1];
        while (true)
        {
            var read = await stream.ReadAsync(oneByte, cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException("The handshake stream closed unexpectedly.");
            }

            if (oneByte[0] == (byte)'\n')
            {
                return Encoding.UTF8.GetString(buffer.ToArray());
            }

            buffer.WriteByte(oneByte[0]);
        }
    }

    private static async Task WriteLineAsync(Stream stream, string line, CancellationToken cancellationToken)
    {
        var bytes = Encoding.UTF8.GetBytes(line + "\n");
        await stream.WriteAsync(bytes, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    private static EnvelopeMessage DecryptMessage(byte[] encrypted, byte[] sessionKey)
    {
        var plaintext = VaultCrypto.DecryptBytes(encrypted, sessionKey);
        return JsonSerializer.Deserialize<EnvelopeMessage>(plaintext, SerializerOptions)
            ?? throw new InvalidOperationException("Secure message could not be parsed.");
    }
}

public sealed class VaultViewerClient : IAsyncDisposable
{
    private readonly TcpClient _tcpClient;
    private readonly SecureChannel _channel;

    private VaultViewerClient(TcpClient tcpClient, SecureChannel channel)
    {
        _tcpClient = tcpClient;
        _channel = channel;
    }

    public static async Task<VaultViewerClient> ConnectAsync(
        string host,
        int port,
        string sessionCode,
        string deviceName,
        CancellationToken cancellationToken = default)
    {
        var tcpClient = new TcpClient();
        await tcpClient.ConnectAsync(host, port, cancellationToken);
        var channel = await SecureChannel.OpenClientAsync(
            tcpClient.GetStream(),
            sessionCode,
            deviceName,
            cancellationToken);
        return new VaultViewerClient(tcpClient, channel);
    }

    public async Task<IReadOnlyList<CatalogItemDto>> GetCatalogAsync(CancellationToken cancellationToken = default)
    {
        await _channel.SendAsync(new EnvelopeMessage
        {
            Type = "catalog-request",
            RequestId = Guid.NewGuid().ToString("N")
        }, cancellationToken);

        var response = await _channel.ReceiveAsync(cancellationToken);
        if (!string.Equals(response.Type, "catalog-response", StringComparison.Ordinal))
        {
            throw new InvalidOperationException(response.Message ?? "Catalog response was invalid.");
        }

        return response.CatalogItems ?? [];
    }

    public async Task<FilePayloadDto> OpenItemAsync(string itemId, CancellationToken cancellationToken = default)
    {
        await _channel.SendAsync(new EnvelopeMessage
        {
            Type = "file-request",
            ItemId = itemId,
            RequestId = Guid.NewGuid().ToString("N")
        }, cancellationToken);

        var response = await _channel.ReceiveAsync(cancellationToken);
        if (!string.Equals(response.Type, "file-response", StringComparison.Ordinal) || response.File is null)
        {
            throw new InvalidOperationException(response.Message ?? "File response was invalid.");
        }

        return response.File;
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            await _channel.SendAsync(new EnvelopeMessage
            {
                Type = "close"
            });
        }
        catch
        {
            // Ignore close errors on shutdown.
        }

        await _channel.DisposeAsync();
        _tcpClient.Dispose();
    }
}
