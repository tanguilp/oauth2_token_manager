defmodule OAuth2TokenManager.Utils do
  @moduledoc false

  @spec server_metadata(
    OAuth2TokenManager.issuer(),
    OAuth2TokenManager.opts()
  ) :: OAuth2TokenManager.server_metadata()
  def server_metadata(iss, opts) do
    local_metadata = opts[:server_metadata] || %{}

    Oauth2MetadataUpdater.get_metadata(iss, opts[:oauth2_metadata_updater_opts] || [])
    |> case do
      {:ok, %{} = server_metadata} ->
        Map.merge(server_metadata, local_metadata)

      {:error, _} ->
        local_metadata
    end
  end

  @spec server_jwks(
    OAuth2TokenManager.issuer(),
    OAuth2TokenManager.opts()
  ) :: [JOSEUtils.JWK.t()]
  def server_jwks(iss, opts) do
    case server_metadata(iss, opts) do
      %{"jwks" => %{"keys" => jwks}} ->
        jwks

      %{"jwks_uri" => jwks_uri} ->
        case JWKSURIUpdater.get_keys(jwks_uri) do
          {:ok, jwks} ->
            jwks

          {:error, _} ->
            []
        end

      _ ->
        []
    end
  end
end
