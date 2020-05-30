defmodule OAuth2TokenManager.Endpoint do
  @moduledoc false

  alias OAuth2TokenManager.{
    MissingServerMetadataError,
    Utils
  }
  alias TeslaOAuth2ClientAuth.UnsupportedClientAuthenticationMethod

  @spec url(
    OAuth2TokenManager.issuer(),
    OAuth2TokenManager.endpoint(),
    OAuth2TokenManager.opts()
  ) :: {:ok, String.t()} | {:error, Exception.t()}
  def url(iss, endpoint, opts) do
    endpoint_name = to_string(endpoint) <> "_endpoint"

    case Utils.server_metadata(iss, opts) do
      %{^endpoint_name => endpoint_url} ->
        {:ok, endpoint_url}

      _ ->
        {:error, %MissingServerMetadataError{field: endpoint_name}}
    end
  end

  @spec http_client(
    OAuth2TokenManager.issuer(),
    OAuth2TokenManager.endpoint(),
    OAuth2TokenManager.client_config(),
    OAuth2TokenManager.opts()
  ) :: {:ok, Tesla.Client.t()} | {:error, Exception.t()}
  def http_client(_iss, :userinfo, _client_conf, _opts) do
    middlewares =
      [
        Tesla.Middleware.DecodeJson
        | Application.get_env(:oauth2_token_manager, :tesla_middlewares, [])
      ]

    {:ok, Tesla.client(middlewares)}
  end

  def http_client(iss, _endpoint, client_conf, opts) do
    auth_method =
      Utils.server_metadata(iss, opts)
      |> Map.get("token_endpoint_auth_method", "client_secret_basic")

    case TeslaOAuth2ClientAuth.implementation(auth_method) do
      {:ok, authenticator} ->
        middleware_opts = Map.merge(
          opts[:tesla_auth_middleware_opts] || %{},
          %{
            client_config: client_conf,
            server_metadata: Utils.server_metadata(iss, opts)
          }
        )

        middlewares =
          [
            {authenticator, middleware_opts},
            Tesla.Middleware.FormUrlencoded,
            Tesla.Middleware.DecodeJson
          ]
          ++ (opts[:tesla_middlewares] || [])
          ++ Application.get_env(:oauth2_token_manager, :tesla_middlewares, [])

        {:ok, Tesla.client(middlewares)}

      {:error, _} ->
        {:error, %UnsupportedClientAuthenticationMethod{requested_method: auth_method}}
    end
  end
end
