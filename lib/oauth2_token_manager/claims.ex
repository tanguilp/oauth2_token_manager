defmodule OAuth2TokenManager.Claims do
  alias OAuth2TokenManager.{
    AccessToken,
    Endpoint,
    HTTPRequestError,
    HTTPStatusError,
    InvalidIDTokenRegistrationError,
    MissingClientMetadataError,
    MissingServerMetadataError,
    Store,
    UserinfoEndpointDecryptionFailureError,
    UserinfoEndpointInvalidContentTypeError,
    UserinfoEndpointVerificationFailureError,
    Utils
  }

  @id_token_default_claims [
    "iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "azp"
  ]

  @doc """
  Returns an ID token for the subject

  The latest retrieved ID token is returned (unless `register_id_token/2` was called by a third-
  party library). It is always unencrypted, but may not be valid anymore (it may have expired).

  If there is no ID token registered, `{:ok, nil}` is returned. The `{:error, e}` tuple is
  returned only when something went wrong with the backend store.
  """
  @spec get_id_token(OAuth2TokenManager.issuer(), OAuth2TokenManager.subject()) ::
  {:ok, OAuth2TokenManager.id_token()}
  | {:ok, nil}
  | {:error, Exception.t()}
  def get_id_token(iss, sub) do
    Store.get_id_token(iss, sub)
  end

  @doc """
  Register a new ID token

  Ideally, only the latest retrieved ID token should be saved using this function.
  """
  @spec register_id_token(
    OAuth2TokenManager.issuer(),
    OAuth2TokenManager.id_token()
  ) :: :ok | {:error, Exception.t()}
  def register_id_token(iss, <<_::binary>> = id_token) do
    if JOSEUtils.is_jws?(id_token) do
      sub =
        id_token
        |> JOSE.JWS.peek_payload()
        |> Jason.decode!()
        |> Map.get("sub")

      Store.put_id_token(iss, sub, id_token)
    else
      {:error, %InvalidIDTokenRegistrationError{}}
    end
  end

  @doc """
  Returns the claims for a subject

  It merges the claims retrieved from the `userinfo` endpoint and those in the ID token returned
  by `get_id_token/2`. The claims of the most recent source take precedence over the others.

  ID token "technical" claims are removed from the output: #{inspect(@id_token_default_claims)}
  """
  @spec get_claims(
    OAuth2TokenManager.issuer(),
    OAuth2TokenManager.subject(),
    OAuth2TokenManager.client_config(),
    OAuth2TokenManager.opts()
  ) :: {:ok, OAuth2TokenManager.claims()} | {:error, Exception.t()}
  def get_claims(iss, sub, client_conf, opts \\ []) do
    opts = OAuth2TokenManager.opts_set_default(opts)

    with {:ok, {claims_or_nil, updated_at}} <- Store.get_claims(iss, sub),
         {:ok, id_token_or_nil} <- Store.get_id_token(iss, sub) do
      if updated_at != nil and now() - updated_at < opts[:min_userinfo_refresh_interval] do
        {:ok, return_claims(id_token_or_nil, claims_or_nil, updated_at)}
      else
        do_get(iss, sub, client_conf, opts)
      end
    end
  end

  defp do_get(iss, sub, client_conf, opts) do
    with {:ok, userinfo_url} <- Endpoint.url(iss, :userinfo, opts),
         {:ok, client} <- Endpoint.http_client(iss, :userinfo, client_conf, opts),
         {:ok, {at, _token_type}} <- AccessToken.get(iss, sub, client_conf, nil, opts) do
      case Tesla.get(client, userinfo_url, headers: [{"authorization", "Bearer " <> at}]) do
        {:ok, %Tesla.Env{status: 200, body: %{} = claims}} ->
          save_and_return_claims(iss, sub, claims)

        # response is either signed or encrypted
        {:ok, %Tesla.Env{status: 200, body: <<_::binary>> = body, headers: headers}} ->
          with :ok <- verify_content_type(headers),
               {:ok, jws} <- maybe_decrypt(body, client_conf),
               {:ok, claims} <- verify_signature(jws, iss, opts) do
          save_and_return_claims(iss, sub, claims)
        end

        {:ok, %Tesla.Env{status: status}} ->
          {:error, %HTTPStatusError{endpoint: :revocation, status: status}}

        {:error, reason} ->
          {:error, %HTTPRequestError{endpoint: :revocation, reason: reason}}
      end
    end
  end

  defp save_and_return_claims(iss, sub, userinfo_claims) do
    with :ok <- Store.put_claims(iss, sub, userinfo_claims),
         {:ok, maybe_id_token} <- get_id_token(iss, sub) do
      {:ok, return_claims(maybe_id_token, userinfo_claims, now())}
    end
  end

  defp return_claims(id_token_or_nil, nil, _) do
    return_claims(id_token_or_nil, %{}, 0)
  end

  defp return_claims(nil, claims, _) do
    claims
  end

  defp return_claims(id_token, claims, claims_updated_at) do
    id_token_claims =
      id_token
      |> JOSE.JWS.peek_payload()
      |> Jason.decode!()

    id_token_returned_claims =
      id_token_claims
      |> Enum.filter(fn {k, _v} -> k not in @id_token_default_claims end)
      |> Enum.into(%{})

    if id_token_claims["iat"] > claims_updated_at do
      Map.merge(claims, id_token_returned_claims)
    else
      Map.merge(id_token_returned_claims, claims)
    end
  end

  defp verify_content_type(headers) do
    Enum.any?(
      headers,
      fn {name, value} ->
        String.downcase(name) == "content-type" and String.downcase(value) == "application/jwt"
      end
    )
    |> if do
      :ok
    else
      {:error, %UserinfoEndpointInvalidContentTypeError{}}
    end
  end

  defp maybe_decrypt(body, client_conf) do
    if JOSEUtils.is_jwe?(body) do
      enc_alg = client_conf["userinfo_encrypted_response_alg"]
      enc_enc = client_conf["userinfo_encrypted_response_enc"] || "A128CBC-HS256"
      jwks = client_jwks(client_conf)

      cond do
        enc_alg && jwks ->
          case JOSEUtils.JWE.decrypt(body, jwks, [enc_alg], [enc_enc]) do
            {:ok, {jws_str, _jwk}} ->
              Jason.decode(jws_str)

            :error ->
              {:error, %UserinfoEndpointDecryptionFailureError{}}
          end

        is_nil(enc_alg) ->
          {:error, %MissingClientMetadataError{field: "userinfo_encrypted_response_alg"}}

        is_nil(jwks) ->
          {:error, %MissingClientMetadataError{field: "jwks"}}
      end
    else
      {:ok, body}
    end
  end

  defp verify_signature(jws, iss, opts) do
    sig_alg = Utils.server_metadata(iss, opts)["userinfo_signed_response_alg"]
    jwks = Utils.server_jwks(iss, opts)

    cond do
      sig_alg && jwks != [] ->
        case JOSEUtils.JWS.verify(jws, jwks, [sig_alg]) do
          {:ok, {content, _jwk}} ->
            Jason.decode(content)

          :error ->
            {:error, %UserinfoEndpointVerificationFailureError{}}
        end

      is_nil(sig_alg) ->
        {:error, %MissingServerMetadataError{field: "jwks"}}

      jwks == [] ->
        {:error, %MissingServerMetadataError{field: "jwks"}}
    end
  end

  defp client_jwks(%{"jwks" => %{"keys" => jwks}}) when is_list(jwks) do
    jwks
  end

  defp client_jwks(%{"jwks_uri" => jwks_uri}) do
    case JWKSURIUpdater.get_keys(jwks_uri) do
      {:ok, jwks} ->
        jwks

      {:error, _} ->
        nil
    end
  end

  defp client_jwks(_) do
    nil
  end

  defp now, do: System.system_time(:second)
end
