using System.Text.Json.Serialization;
using SecureGalleryVault.Core;
using SecureGalleryVault.SharedServer;

var builder = WebApplication.CreateBuilder(args);

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
});
builder.Services.AddSingleton<HostedSharedSpaceRepository>();

var app = builder.Build();

app.MapGet("/", () => Results.Ok(new
{
    service = "Secure Gallery Vault Shared Server",
    status = "ok"
}));

app.MapGet("/health", () => Results.Ok(new { status = "ok" }));

app.MapPost("/api/bootstrap/request", (
    HttpRequest httpRequest,
    EnvelopeMessage request,
    HostedSharedSpaceRepository repository) =>
{
    var sessionCode = httpRequest.Headers["X-SGV-Session-Code"].ToString();
    if (!repository.MatchesBootstrapCode(sessionCode))
    {
        return Denied(request, "Shared backend access was denied.");
    }

    try
    {
        return Results.Json(HandleBootstrapRequest(repository, request));
    }
    catch (Exception exception)
    {
        return Failure(request, exception.Message);
    }
});

app.MapPost("/api/spaces/{spaceId}/request", (
    string spaceId,
    HttpRequest httpRequest,
    EnvelopeMessage request,
    HostedSharedSpaceRepository repository) =>
{
    var sessionCode = httpRequest.Headers["X-SGV-Session-Code"].ToString();
    if (!repository.TryAuthorizeSpace(spaceId, sessionCode, out var authorizedSpace))
    {
        return Denied(request, "Shared space access was denied.");
    }

    try
    {
        request.SpaceId ??= spaceId;
        return Results.Json(HandleSpaceRequest(repository, authorizedSpace, request));
    }
    catch (Exception exception)
    {
        return Failure(request, exception.Message);
    }
});

app.Run();

static EnvelopeMessage HandleBootstrapRequest(HostedSharedSpaceRepository repository, EnvelopeMessage request)
{
    return request.Type switch
    {
        "user-register" => HandleUserRegister(repository, request),
        "user-search-request" => new EnvelopeMessage
        {
            Type = "user-search-response",
            RequestId = request.RequestId,
            Users = repository.SearchUsers(request.Query ?? string.Empty).ToList()
        },
        "space-create" => HandleSpaceCreate(repository, request),
        "space-list-request" => new EnvelopeMessage
        {
            Type = "space-list-response",
            RequestId = request.RequestId,
            Spaces = string.IsNullOrWhiteSpace(request.User?.UserId)
                ? repository.GetSpaces().ToList()
                : repository.GetSpacesForUser(request.User!.UserId).ToList()
        },
        "space-add-member" => HandleSpaceAddMember(repository, request),
        _ => new EnvelopeMessage
        {
            Type = "error",
            RequestId = request.RequestId,
            Message = "Unsupported server-management request."
        }
    };
}

static EnvelopeMessage HandleUserRegister(HostedSharedSpaceRepository repository, EnvelopeMessage request)
{
    var displayName = request.User?.DisplayName ?? request.Message ?? string.Empty;
    if (string.IsNullOrWhiteSpace(displayName))
    {
        throw new InvalidOperationException("A display name is required to register a shared-space user.");
    }

    return new EnvelopeMessage
    {
        Type = "user-register-response",
        RequestId = request.RequestId,
        User = repository.RegisterUser(displayName.Trim())
    };
}

static EnvelopeMessage HandleSpaceCreate(HostedSharedSpaceRepository repository, EnvelopeMessage request)
{
    var displayName = request.Space?.DisplayName ?? request.Message ?? string.Empty;
    if (string.IsNullOrWhiteSpace(displayName))
    {
        throw new InvalidOperationException("Shared space name is required.");
    }

    var created = string.IsNullOrWhiteSpace(request.User?.UserId)
        ? repository.CreateSpace(displayName.Trim())
        : repository.CreateSpace(displayName.Trim(), request.User!.UserId);

    return new EnvelopeMessage
    {
        Type = "space-create-response",
        RequestId = request.RequestId,
        Space = created
    };
}

static EnvelopeMessage HandleSpaceAddMember(HostedSharedSpaceRepository repository, EnvelopeMessage request)
{
    if (string.IsNullOrWhiteSpace(request.SpaceId) || string.IsNullOrWhiteSpace(request.TargetUserId))
    {
        throw new InvalidOperationException("A shared space id and target user id are required.");
    }

    return new EnvelopeMessage
    {
        Type = "space-add-member-response",
        RequestId = request.RequestId,
        Space = repository.AddMember(request.SpaceId, request.TargetUserId)
    };
}

static EnvelopeMessage HandleSpaceRequest(
    HostedSharedSpaceRepository repository,
    SharedSpaceDto space,
    EnvelopeMessage request)
{
    return request.Type switch
    {
        "space-info-request" => new EnvelopeMessage
        {
            Type = "space-info-response",
            RequestId = request.RequestId,
            Space = repository.GetSpace(space.SpaceId)
        },
        "catalog-request" => new EnvelopeMessage
        {
            Type = "catalog-response",
            RequestId = request.RequestId,
            Space = repository.GetSpace(space.SpaceId),
            CatalogItems = repository.BuildCatalog(space.SpaceId).ToList()
        },
        "file-request" => new EnvelopeMessage
        {
            Type = "file-response",
            RequestId = request.RequestId,
            File = repository.BuildFilePayload(space.SpaceId, request.ItemId ?? string.Empty)
        },
        "space-upload" => HandleSpaceUpload(repository, space, request),
        _ => new EnvelopeMessage
        {
            Type = "error",
            RequestId = request.RequestId,
            Message = "Unsupported shared-space request."
        }
    };
}

static EnvelopeMessage HandleSpaceUpload(
    HostedSharedSpaceRepository repository,
    SharedSpaceDto space,
    EnvelopeMessage request)
{
    var payload = request.File
        ?? throw new InvalidOperationException("Shared upload payload was missing.");
    repository.SaveIncomingPayload(space.SpaceId, payload, request.DeviceName);
    return new EnvelopeMessage
    {
        Type = "space-upload-ok",
        RequestId = request.RequestId,
        Message = $"Stored in {space.DisplayName}.",
        Space = repository.GetSpace(space.SpaceId)
    };
}

static IResult Failure(EnvelopeMessage request, string message)
{
    return Results.Json(
        new EnvelopeMessage
        {
            Type = "error",
            RequestId = request.RequestId,
            Message = message
        },
        statusCode: StatusCodes.Status400BadRequest);
}

static IResult Denied(EnvelopeMessage request, string message)
{
    return Results.Json(
        new EnvelopeMessage
        {
            Type = "error",
            RequestId = request.RequestId,
            Message = message
        },
        statusCode: StatusCodes.Status403Forbidden);
}
