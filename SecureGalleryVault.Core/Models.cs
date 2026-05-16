namespace SecureGalleryVault.Core;

public static class VaultConstants
{
    public const int DefaultPort = 47555;
    public const int SharedServerPort = 47565;
    public const int Pbkdf2Iterations = 200_000;
    public const int ThumbnailEdge = 720;
    public const int MaxInMemoryImportBytes = 64 * 1024 * 1024;
    public const int MaxInlinePreviewBytes = 20 * 1024 * 1024;
}

public static class VaultSpaces
{
    public const string Private = "vault";
    public const string Shared = "shared";
}

public sealed class VaultConfig
{
    public string SaltBase64 { get; set; } = string.Empty;
    public string MasterKeyPacketBase64 { get; set; } = string.Empty;
    public DateTimeOffset CreatedUtc { get; set; }
}

public sealed class VaultIndex
{
    public List<VaultItemRecord> Items { get; set; } = [];
}

public sealed class VaultItemRecord
{
    public string Id { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string MimeType { get; set; } = "application/octet-stream";
    public string PreviewKind { get; set; } = "file";
    public string ExtensionLabel { get; set; } = "FILE";
    public long Size { get; set; }
    public DateTimeOffset ImportedUtc { get; set; }
    public string EncryptedFileName { get; set; } = string.Empty;
    public string? EncryptedThumbnailFileName { get; set; }
    public string SpaceId { get; set; } = VaultSpaces.Private;
    public string? SourceDeviceName { get; set; }
}

public sealed class CatalogItemDto
{
    public string Id { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string MimeType { get; set; } = "application/octet-stream";
    public string PreviewKind { get; set; } = "file";
    public string ExtensionLabel { get; set; } = "FILE";
    public long Size { get; set; }
    public DateTimeOffset ImportedUtc { get; set; }
    public string? ThumbnailBase64 { get; set; }
    public string SpaceId { get; set; } = VaultSpaces.Private;
    public string? SourceDeviceName { get; set; }
}

public sealed class FilePayloadDto
{
    public string Id { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string MimeType { get; set; } = "application/octet-stream";
    public long Size { get; set; }
    public string? ThumbnailBase64 { get; set; }
    public string ContentBase64 { get; set; } = string.Empty;
}

public sealed class SharedSpaceDto
{
    public string SpaceId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string AccessCode { get; set; } = string.Empty;
    public DateTimeOffset CreatedUtc { get; set; }
    public int ItemCount { get; set; }
    public string? OwnerUserId { get; set; }
    public string? OwnerDisplayName { get; set; }
    public List<SharedSpaceMemberDto> Members { get; set; } = [];
}

public sealed class SharedSpaceMemberDto
{
    public string UserId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
}

public sealed class UserProfileDto
{
    public string UserId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public DateTimeOffset CreatedUtc { get; set; }
    public DateTimeOffset? LastSeenUtc { get; set; }
}

public sealed class HelloPacket
{
    public string Role { get; set; } = string.Empty;
    public string NonceBase64 { get; set; } = string.Empty;
    public string PublicKeyBase64 { get; set; } = string.Empty;
    public string DeviceName { get; set; } = string.Empty;
    public int ProtocolVersion { get; set; } = 1;
}

public sealed class EnvelopeMessage
{
    public string Type { get; set; } = string.Empty;
    public string? RequestId { get; set; }
    public string? Message { get; set; }
    public string? Query { get; set; }
    public string? ItemId { get; set; }
    public string? SpaceId { get; set; }
    public string? TargetUserId { get; set; }
    public string? DeviceName { get; set; }
    public List<CatalogItemDto>? CatalogItems { get; set; }
    public SharedSpaceDto? Space { get; set; }
    public List<SharedSpaceDto>? Spaces { get; set; }
    public UserProfileDto? User { get; set; }
    public List<UserProfileDto>? Users { get; set; }
    public FilePayloadDto? File { get; set; }
}
