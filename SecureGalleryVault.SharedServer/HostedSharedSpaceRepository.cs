using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecureGalleryVault.Core;

namespace SecureGalleryVault.SharedServer;

internal sealed class HostedSharedSpaceRepository
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true
    };

    private readonly object _sync = new();
    private readonly string _rootDirectory;
    private readonly string _spacesDirectory;
    private readonly string _statePath;
    private readonly string _masterKeyPath;

    private HostedSharedSpaceState _state;

    public HostedSharedSpaceRepository()
    {
        _rootDirectory = ResolveRootDirectory();
        _spacesDirectory = Path.Combine(_rootDirectory, "spaces");
        _statePath = Path.Combine(_rootDirectory, "server-state.json");
        _masterKeyPath = Path.Combine(_rootDirectory, "server-masterkey.bin");

        Directory.CreateDirectory(_rootDirectory);
        Directory.CreateDirectory(_spacesDirectory);
        _state = LoadState();
        EnsureMasterKeyExists();
    }

    public string BootstrapCode => _state.BootstrapCode;

    public bool MatchesBootstrapCode(string candidate)
    {
        return string.Equals(candidate?.Trim(), BootstrapCode, StringComparison.Ordinal);
    }

    public bool TryAuthorizeSpace(string spaceId, string accessCode, out SharedSpaceDto space)
    {
        lock (_sync)
        {
            var record = _state.Spaces.FirstOrDefault(item =>
                string.Equals(item.SpaceId, spaceId, StringComparison.Ordinal)
                && string.Equals(item.AccessCode, accessCode?.Trim(), StringComparison.Ordinal));

            if (record is null)
            {
                space = new SharedSpaceDto();
                return false;
            }

            space = MapSpace(record);
            return true;
        }
    }

    public IReadOnlyList<SharedSpaceDto> GetSpaces()
    {
        lock (_sync)
        {
            return _state.Spaces
                .Select(MapSpace)
                .OrderByDescending(space => space.CreatedUtc)
                .ThenBy(space => space.DisplayName, StringComparer.CurrentCultureIgnoreCase)
                .ToList();
        }
    }

    public IReadOnlyList<SharedSpaceDto> GetSpacesForUser(string userId)
    {
        lock (_sync)
        {
            return _state.Spaces
                .Where(space => space.MemberUserIds.Contains(userId, StringComparer.Ordinal))
                .Select(MapSpace)
                .OrderByDescending(space => space.CreatedUtc)
                .ThenBy(space => space.DisplayName, StringComparer.CurrentCultureIgnoreCase)
                .ToList();
        }
    }

    public SharedSpaceDto? GetSpace(string spaceId)
    {
        lock (_sync)
        {
            return _state.Spaces
                .Where(space => string.Equals(space.SpaceId, spaceId, StringComparison.Ordinal))
                .Select(MapSpace)
                .FirstOrDefault();
        }
    }

    public UserProfileDto RegisterUser(string displayName)
    {
        lock (_sync)
        {
            var trimmedName = displayName.Trim();
            if (string.IsNullOrWhiteSpace(trimmedName))
            {
                throw new InvalidOperationException("A display name is required.");
            }

            var normalized = NormalizeDisplayName(trimmedName);
            var now = DateTimeOffset.UtcNow;
            var record = _state.Users.FirstOrDefault(user =>
                string.Equals(NormalizeDisplayName(user.DisplayName), normalized, StringComparison.Ordinal));

            if (record is null)
            {
                record = new HostedSharedUserRecord
                {
                    UserId = Guid.NewGuid().ToString("N"),
                    DisplayName = trimmedName,
                    CreatedUtc = now,
                    LastSeenUtc = now
                };
                _state.Users.Add(record);
            }
            else
            {
                record.DisplayName = trimmedName;
                record.LastSeenUtc = now;
            }

            SaveState();
            return MapUser(record);
        }
    }

    public IReadOnlyList<UserProfileDto> SearchUsers(string query)
    {
        lock (_sync)
        {
            var normalized = NormalizeDisplayName(query);
            return _state.Users
                .Where(user =>
                    string.IsNullOrWhiteSpace(normalized)
                    || NormalizeDisplayName(user.DisplayName).Contains(normalized, StringComparison.Ordinal))
                .OrderBy(user => user.DisplayName, StringComparer.CurrentCultureIgnoreCase)
                .Take(20)
                .Select(MapUser)
                .ToList();
        }
    }

    public SharedSpaceDto CreateSpace(string displayName, string? ownerUserId = null)
    {
        lock (_sync)
        {
            var trimmedName = displayName.Trim();
            if (string.IsNullOrWhiteSpace(trimmedName))
            {
                throw new InvalidOperationException("A shared space name is required.");
            }

            if (!string.IsNullOrWhiteSpace(ownerUserId)
                && _state.Users.All(user => !string.Equals(user.UserId, ownerUserId, StringComparison.Ordinal)))
            {
                throw new InvalidOperationException("The shared-space owner is not registered on this server.");
            }

            var record = new HostedSharedSpaceRecord
            {
                SpaceId = Guid.NewGuid().ToString("N"),
                DisplayName = trimmedName,
                AccessCode = CreateUniqueAccessCode(),
                CreatedUtc = DateTimeOffset.UtcNow,
                OwnerUserId = ownerUserId
            };

            if (!string.IsNullOrWhiteSpace(ownerUserId))
            {
                record.MemberUserIds.Add(ownerUserId);
            }

            _state.Spaces.Add(record);
            EnsureSpaceDirectories(record.SpaceId);
            SaveState();
            return MapSpace(record);
        }
    }

    public SharedSpaceDto AddMember(string spaceId, string userId)
    {
        lock (_sync)
        {
            var record = _state.Spaces.FirstOrDefault(space => string.Equals(space.SpaceId, spaceId, StringComparison.Ordinal))
                ?? throw new InvalidOperationException("The shared space was not found.");
            if (_state.Users.All(user => !string.Equals(user.UserId, userId, StringComparison.Ordinal)))
            {
                throw new InvalidOperationException("That user is not registered on this server.");
            }

            if (!record.MemberUserIds.Contains(userId, StringComparer.Ordinal))
            {
                record.MemberUserIds.Add(userId);
                SaveState();
            }

            return MapSpace(record);
        }
    }

    public IReadOnlyList<CatalogItemDto> BuildCatalog(string spaceId)
    {
        lock (_sync)
        {
            return LoadSpaceIndex(spaceId).Items
                .OrderByDescending(item => item.ImportedUtc)
                .Select(item => new CatalogItemDto
                {
                    Id = item.Id,
                    DisplayName = item.DisplayName,
                    MimeType = item.MimeType,
                    PreviewKind = item.PreviewKind,
                    ExtensionLabel = item.ExtensionLabel,
                    Size = item.Size,
                    ImportedUtc = item.ImportedUtc,
                    ThumbnailBase64 = LoadThumbnailBase64(spaceId, item),
                    SpaceId = item.SpaceId,
                    SourceDeviceName = item.SourceDeviceName
                })
                .ToList();
        }
    }

    public FilePayloadDto BuildFilePayload(string spaceId, string itemId)
    {
        lock (_sync)
        {
            var index = LoadSpaceIndex(spaceId);
            var item = index.Items.FirstOrDefault(entry => string.Equals(entry.Id, itemId, StringComparison.Ordinal))
                ?? throw new InvalidOperationException("Shared space item was not found.");
            if (item.Size > VaultConstants.MaxInlinePreviewBytes)
            {
                throw new InvalidOperationException("This viewer currently previews files up to 20 MB.");
            }

            var encryptedPath = Path.Combine(GetSpaceItemsDirectory(spaceId), item.EncryptedFileName);
            var encryptedBytes = File.ReadAllBytes(encryptedPath);
            var masterKey = ReadMasterKey();
            try
            {
                var bytes = VaultCrypto.DecryptBytes(encryptedBytes, masterKey);
                try
                {
                    return new FilePayloadDto
                    {
                        Id = item.Id,
                        DisplayName = item.DisplayName,
                        MimeType = item.MimeType,
                        Size = item.Size,
                        ThumbnailBase64 = LoadThumbnailBase64(spaceId, item),
                        ContentBase64 = Convert.ToBase64String(bytes)
                    };
                }
                finally
                {
                    VaultCrypto.Zero(bytes);
                }
            }
            finally
            {
                VaultCrypto.Zero(masterKey);
                VaultCrypto.Zero(encryptedBytes);
            }
        }
    }

    public void SaveIncomingPayload(string spaceId, FilePayloadDto payload, string? sourceDeviceName)
    {
        lock (_sync)
        {
            var index = LoadSpaceIndex(spaceId);
            var masterKey = ReadMasterKey();
            var bytes = Convert.FromBase64String(payload.ContentBase64);
            try
            {
                if (bytes.Length > VaultConstants.MaxInMemoryImportBytes)
                {
                    throw new InvalidOperationException("Shared uploads are capped at 64 MB per file.");
                }

                EnsureSpaceDirectories(spaceId);
                var itemId = string.IsNullOrWhiteSpace(payload.Id) ? Guid.NewGuid().ToString("N") : payload.Id;
                DeleteExistingItemFiles(spaceId, index, itemId);

                var encryptedFileName = $"{itemId}.bin";
                string? encryptedThumbnailFileName = null;
                var encryptedBytes = VaultCrypto.EncryptBytes(bytes, masterKey);
                try
                {
                    File.WriteAllBytes(Path.Combine(GetSpaceItemsDirectory(spaceId), encryptedFileName), encryptedBytes);
                }
                finally
                {
                    VaultCrypto.Zero(encryptedBytes);
                }

                if (!string.IsNullOrWhiteSpace(payload.ThumbnailBase64))
                {
                    var thumbnailBytes = Convert.FromBase64String(payload.ThumbnailBase64);
                    if (thumbnailBytes.Length > 0)
                    {
                        encryptedThumbnailFileName = $"{itemId}.thumb.bin";
                        var encryptedThumbnailBytes = VaultCrypto.EncryptBytes(thumbnailBytes, masterKey);
                        try
                        {
                            File.WriteAllBytes(
                                Path.Combine(GetSpaceItemsDirectory(spaceId), encryptedThumbnailFileName),
                                encryptedThumbnailBytes);
                        }
                        finally
                        {
                            VaultCrypto.Zero(encryptedThumbnailBytes);
                            VaultCrypto.Zero(thumbnailBytes);
                        }
                    }
                }

                index.Items.Add(new VaultItemRecord
                {
                    Id = itemId,
                    DisplayName = string.IsNullOrWhiteSpace(payload.DisplayName) ? $"Upload-{itemId}" : payload.DisplayName,
                    MimeType = payload.MimeType,
                    PreviewKind = payload.MimeType.StartsWith("image/", StringComparison.OrdinalIgnoreCase) ? "image" : "file",
                    ExtensionLabel = BuildExtensionLabel(payload.DisplayName),
                    Size = payload.Size,
                    ImportedUtc = DateTimeOffset.UtcNow,
                    EncryptedFileName = encryptedFileName,
                    EncryptedThumbnailFileName = encryptedThumbnailFileName,
                    SpaceId = spaceId,
                    SourceDeviceName = string.IsNullOrWhiteSpace(sourceDeviceName) ? null : sourceDeviceName
                });

                SaveSpaceIndex(spaceId, index);
            }
            finally
            {
                VaultCrypto.Zero(masterKey);
                VaultCrypto.Zero(bytes);
            }
        }
    }

    private HostedSharedSpaceState LoadState()
    {
        var bootstrapCode = Environment.GetEnvironmentVariable("SGV_BOOTSTRAP_CODE")?.Trim();
        if (!File.Exists(_statePath))
        {
            var created = new HostedSharedSpaceState
            {
                BootstrapCode = string.IsNullOrWhiteSpace(bootstrapCode) ? CreateAccessCode() : bootstrapCode
            };
            File.WriteAllText(_statePath, JsonSerializer.Serialize(created, JsonOptions));
            return created;
        }

        try
        {
            var text = File.ReadAllText(_statePath);
            var loaded = JsonSerializer.Deserialize<HostedSharedSpaceState>(text, JsonOptions)
                ?? new HostedSharedSpaceState();
            if (!string.IsNullOrWhiteSpace(bootstrapCode) && !string.Equals(loaded.BootstrapCode, bootstrapCode, StringComparison.Ordinal))
            {
                loaded.BootstrapCode = bootstrapCode;
                File.WriteAllText(_statePath, JsonSerializer.Serialize(loaded, JsonOptions));
            }
            else if (string.IsNullOrWhiteSpace(loaded.BootstrapCode))
            {
                loaded.BootstrapCode = string.IsNullOrWhiteSpace(bootstrapCode) ? CreateAccessCode() : bootstrapCode;
                File.WriteAllText(_statePath, JsonSerializer.Serialize(loaded, JsonOptions));
            }

            return loaded;
        }
        catch
        {
            QuarantineFile(_statePath);
            var recovered = new HostedSharedSpaceState
            {
                BootstrapCode = string.IsNullOrWhiteSpace(bootstrapCode) ? CreateAccessCode() : bootstrapCode
            };
            File.WriteAllText(_statePath, JsonSerializer.Serialize(recovered, JsonOptions));
            return recovered;
        }
    }

    private void SaveState()
    {
        File.WriteAllText(_statePath, JsonSerializer.Serialize(_state, JsonOptions));
    }

    private void EnsureMasterKeyExists()
    {
        if (File.Exists(_masterKeyPath))
        {
            return;
        }

        var masterKey = RandomNumberGenerator.GetBytes(32);
        var protectionKey = ReadProtectionKey();
        try
        {
            var protectedKey = VaultCrypto.EncryptBytes(masterKey, protectionKey);
            File.WriteAllBytes(_masterKeyPath, protectedKey);
        }
        finally
        {
            VaultCrypto.Zero(masterKey);
            VaultCrypto.Zero(protectionKey);
        }
    }

    private byte[] ReadMasterKey()
    {
        var protectedKey = File.ReadAllBytes(_masterKeyPath);
        var protectionKey = ReadProtectionKey();
        try
        {
            return VaultCrypto.DecryptBytes(protectedKey, protectionKey);
        }
        finally
        {
            VaultCrypto.Zero(protectionKey);
            VaultCrypto.Zero(protectedKey);
        }
    }

    private byte[] ReadProtectionKey()
    {
        var secret = Environment.GetEnvironmentVariable("SGV_MASTER_SECRET");
        if (string.IsNullOrWhiteSpace(secret))
        {
            throw new InvalidOperationException("SGV_MASTER_SECRET must be configured before the shared server can start.");
        }

        return SHA256.HashData(Encoding.UTF8.GetBytes(secret));
    }

    private SharedSpaceDto MapSpace(HostedSharedSpaceRecord record)
    {
        var itemCount = LoadSpaceIndex(record.SpaceId).Items.Count;
        var members = record.MemberUserIds
            .Select(userId => _state.Users.FirstOrDefault(user => string.Equals(user.UserId, userId, StringComparison.Ordinal)))
            .Where(user => user is not null)
            .Select(user => new SharedSpaceMemberDto
            {
                UserId = user!.UserId,
                DisplayName = user.DisplayName
            })
            .ToList();
        var owner = _state.Users.FirstOrDefault(user => string.Equals(user.UserId, record.OwnerUserId, StringComparison.Ordinal));

        return new SharedSpaceDto
        {
            SpaceId = record.SpaceId,
            DisplayName = record.DisplayName,
            AccessCode = record.AccessCode,
            CreatedUtc = record.CreatedUtc,
            ItemCount = itemCount,
            OwnerUserId = record.OwnerUserId,
            OwnerDisplayName = owner?.DisplayName,
            Members = members
        };
    }

    private static UserProfileDto MapUser(HostedSharedUserRecord record)
    {
        return new UserProfileDto
        {
            UserId = record.UserId,
            DisplayName = record.DisplayName,
            CreatedUtc = record.CreatedUtc,
            LastSeenUtc = record.LastSeenUtc
        };
    }

    private VaultIndex LoadSpaceIndex(string spaceId)
    {
        var path = GetSpaceIndexPath(spaceId);
        if (!File.Exists(path))
        {
            return new VaultIndex();
        }

        try
        {
            var text = File.ReadAllText(path);
            return JsonSerializer.Deserialize<VaultIndex>(text, JsonOptions) ?? new VaultIndex();
        }
        catch
        {
            QuarantineFile(path);
            return new VaultIndex();
        }
    }

    private void SaveSpaceIndex(string spaceId, VaultIndex index)
    {
        var path = GetSpaceIndexPath(spaceId);
        File.WriteAllText(path, JsonSerializer.Serialize(index, JsonOptions));
    }

    private void DeleteExistingItemFiles(string spaceId, VaultIndex index, string itemId)
    {
        var existing = index.Items.FirstOrDefault(entry => string.Equals(entry.Id, itemId, StringComparison.Ordinal));
        if (existing is null)
        {
            return;
        }

        var itemsDirectory = GetSpaceItemsDirectory(spaceId);
        TryDelete(Path.Combine(itemsDirectory, existing.EncryptedFileName));
        if (!string.IsNullOrWhiteSpace(existing.EncryptedThumbnailFileName))
        {
            TryDelete(Path.Combine(itemsDirectory, existing.EncryptedThumbnailFileName));
        }

        index.Items.Remove(existing);
    }

    private string? LoadThumbnailBase64(string spaceId, VaultItemRecord item)
    {
        if (string.IsNullOrWhiteSpace(item.EncryptedThumbnailFileName))
        {
            return null;
        }

        var thumbnailPath = Path.Combine(GetSpaceItemsDirectory(spaceId), item.EncryptedThumbnailFileName);
        if (!File.Exists(thumbnailPath))
        {
            return null;
        }

        var masterKey = ReadMasterKey();
        var encryptedThumbnailBytes = File.ReadAllBytes(thumbnailPath);
        try
        {
            var thumbnailBytes = VaultCrypto.DecryptBytes(encryptedThumbnailBytes, masterKey);
            try
            {
                return Convert.ToBase64String(thumbnailBytes);
            }
            finally
            {
                VaultCrypto.Zero(thumbnailBytes);
            }
        }
        catch
        {
            return null;
        }
        finally
        {
            VaultCrypto.Zero(masterKey);
            VaultCrypto.Zero(encryptedThumbnailBytes);
        }
    }

    private void EnsureSpaceDirectories(string spaceId)
    {
        Directory.CreateDirectory(GetSpaceDirectory(spaceId));
        Directory.CreateDirectory(GetSpaceItemsDirectory(spaceId));
    }

    private string GetSpaceDirectory(string spaceId) => Path.Combine(_spacesDirectory, spaceId);

    private string GetSpaceItemsDirectory(string spaceId) => Path.Combine(GetSpaceDirectory(spaceId), "items");

    private string GetSpaceIndexPath(string spaceId) => Path.Combine(GetSpaceDirectory(spaceId), "space-index.json");

    private string CreateUniqueAccessCode()
    {
        string accessCode;
        do
        {
            accessCode = CreateAccessCode();
        }
        while (_state.Spaces.Any(space => string.Equals(space.AccessCode, accessCode, StringComparison.Ordinal))
            || string.Equals(accessCode, _state.BootstrapCode, StringComparison.Ordinal));

        return accessCode;
    }

    private static string CreateAccessCode()
    {
        return RandomNumberGenerator.GetInt32(10000000, 99999999).ToString();
    }

    private static string BuildExtensionLabel(string? displayName)
    {
        var extension = Path.GetExtension(displayName ?? string.Empty).TrimStart('.');
        return string.IsNullOrWhiteSpace(extension)
            ? "FILE"
            : extension.ToUpperInvariant()[..Math.Min(4, extension.Length)];
    }

    private static string NormalizeDisplayName(string? value)
    {
        return (value ?? string.Empty).Trim().ToLowerInvariant();
    }

    private static string ResolveRootDirectory()
    {
        var configured = Environment.GetEnvironmentVariable("SGV_DATA_DIR");
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return configured;
        }

        var renderDiskPath = Environment.GetEnvironmentVariable("RENDER_DISK_PATH");
        if (!string.IsNullOrWhiteSpace(renderDiskPath))
        {
            return Path.Combine(renderDiskPath, "sgv-shared");
        }

        return Path.Combine(AppContext.BaseDirectory, "data");
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // Best effort only.
        }
    }

    private static void QuarantineFile(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return;
            }

            var quarantinedPath = path + ".corrupt";
            if (File.Exists(quarantinedPath))
            {
                File.Delete(quarantinedPath);
            }

            File.Move(path, quarantinedPath);
        }
        catch
        {
            // Best-effort recovery only.
        }
    }

    private sealed class HostedSharedSpaceState
    {
        public string BootstrapCode { get; set; } = string.Empty;

        public List<HostedSharedUserRecord> Users { get; set; } = [];

        public List<HostedSharedSpaceRecord> Spaces { get; set; } = [];
    }

    private sealed class HostedSharedUserRecord
    {
        public string UserId { get; set; } = string.Empty;

        public string DisplayName { get; set; } = string.Empty;

        public DateTimeOffset CreatedUtc { get; set; }

        public DateTimeOffset? LastSeenUtc { get; set; }
    }

    private sealed class HostedSharedSpaceRecord
    {
        public string SpaceId { get; set; } = string.Empty;

        public string DisplayName { get; set; } = string.Empty;

        public string AccessCode { get; set; } = string.Empty;

        public DateTimeOffset CreatedUtc { get; set; }

        public string? OwnerUserId { get; set; }

        public List<string> MemberUserIds { get; set; } = [];
    }
}
