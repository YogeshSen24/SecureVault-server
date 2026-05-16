FROM mcr.microsoft.com/dotnet/sdk:9.0 AS build
WORKDIR /src

COPY SecureGalleryVault.Core/SecureGalleryVault.Core.csproj SecureGalleryVault.Core/
COPY SecureGalleryVault.SharedServer/SecureGalleryVault.SharedServer.csproj SecureGalleryVault.SharedServer/
RUN dotnet restore SecureGalleryVault.SharedServer/SecureGalleryVault.SharedServer.csproj

COPY . .
RUN dotnet publish SecureGalleryVault.SharedServer/SecureGalleryVault.SharedServer.csproj -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:9.0 AS final
WORKDIR /app
ENV ASPNETCORE_URLS=http://0.0.0.0:10000
COPY --from=build /app/publish .
EXPOSE 10000
ENTRYPOINT ["dotnet", "SecureGalleryVault.SharedServer.dll"]
