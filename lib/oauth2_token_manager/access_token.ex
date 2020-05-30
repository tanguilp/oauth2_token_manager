defmodule OAuth2TokenManager.AccessToken do
  require Logger

  alias OAuth2TokenManager.{
    Endpoint,
    HTTPRequestError,
    HTTPStatusError,
    NoSuitableAccessTokenFoundError,
    RefreshToken,
    Store
  }

  @doc """
  Registers an access token
  """
  @spec register(
    OAuth2TokenManager.access_token(),
    OAuth2TokenManager.token_type(),
    OAuth2TokenManager.token_metadata(),
    OAuth2TokenManager.issuer(),
    OAuth2TokenManager.client_config(),
    OAuth2TokenManager.opts()
  ) :: {:ok, OAuth2TokenManager.token_metadata()} | {:error, Exception.t()}
  def register(at, at_type, at_metadata, iss, client_conf, opts \\ []) do
    opts = OAuth2TokenManager.opts_set_default(opts)

    if opts[:auto_introspect] == true or at_metadata["sub"] == nil do
      with {:ok, at_metadata} <- introspect(at, iss, client_conf, opts) do
        Store.put_access_token(at, at_type, at_metadata, iss)
      end
    else
      with {:ok, at_metadata} <- scope_param_to_list(at_metadata) do
        Store.put_access_token(at, at_type, at_metadata, iss)
      end
    end
  end

  @doc """
  Introspect an access token

  A request is performed to the introspection endpoint of the authorization server if saved
  metadata is not fresh (`:min_introspect_interval` option, see `t:OAuth2TokenManager.opts/0`).

  The response is **not** saved. Use `register/6` if you want to do so.
  """
  @spec introspect(
    OAuth2TokenManager.access_token(),
    OAuth2TokenManager.issuer(),
    OAuth2TokenManager.client_config(),
    OAuth2TokenManager.opts()
  ) :: {:ok, OAuth2TokenManager.token_metadata()} | {:error, Exception.t()}
  def introspect(at, iss, client_conf, opts \\ []) do
    opts = OAuth2TokenManager.opts_set_default(opts)

    case Store.get_access_token(at) do
      {:ok, {^at, _token_type, at_metadata, updated_at}} ->
        if now() - updated_at < opts[:min_introspect_interval] do
          {:ok, at_metadata}
        else
          do_introspect(at, iss, client_conf, opts)
        end

      {:ok, _} ->
        do_introspect(at, iss, client_conf, opts)

      {:error, _} = error ->
        error
    end
  end

  defp do_introspect(at, iss, client_conf, opts) do
    with {:ok, introspect_url} <- Endpoint.url(iss, :introspection, opts),
         {:ok, client} <- Endpoint.http_client(iss, :introspection, client_conf, opts) do
      body = %{
        token: at,
        token_type_hint: "access_token"
      }

      case Tesla.post(client, introspect_url, body) do
        {:ok, %Tesla.Env{status: 200, body: body}} ->
          scope_param_to_list(body)

        {:ok, %Tesla.Env{status: status}} ->
          Logger.warn("Could not introspect access token `#{hash(at)}` (sha256), reason: " <>
            "invalid HTTP status `#{status}`"
          )

          {:error, %HTTPStatusError{endpoint: :introspection, status: status}}

        {:error, reason} ->
          Logger.warn("Could not introspect access token `#{hash(at)}` (sha256), reason: " <>
            "failed HTTP request `#{inspect(reason)}`"
          )

          {:error, %HTTPRequestError{endpoint: :introspection, reason: reason}}
      end
    end
  end

  @doc """
  Gets an access token for API access

  ## Requesting scopes

  The `requested_scope_or_nil` allows requesting an access token with certain scopes as
  follows:
  - if the parameter is set to a list of scopes (for instance `["scope_a", "scope_b"]`):
    - if there is an existing valid access token available with these exact scopes (and
    **no more**), it returns it
    - otherwise it tries using an refresh token registered for the subject and the issuer
    passed as parameters to retrieve an access token with just these scopes
  - if the parameter is `nil`, returns any valid access token
  """
  @spec get(
    OAuth2TokenManager.issuer(),
    OAuth2TokenManager.subject() | :client_credentials,
    OAuth2TokenManager.client_config(),
    [OAuth2TokenManager.scope()] | nil,
    OAuth2TokenManager.opts()
  ) ::
  {:ok, {OAuth2TokenManager.access_token(), OAuth2TokenManager.token_type()}}
  | {:error, Exception.t()}
  def get(iss, sub_or_cc, client_conf, requested_scope_or_nil, opts \\ []) do
    opts = OAuth2TokenManager.opts_set_default(opts)

    case sub_or_cc do
      <<_::binary>> ->
        Store.get_access_tokens_for_subject(iss, sub_or_cc)

      :client_credentials ->
        Store.get_access_tokens_client_credentials(iss, client_conf["client_id"])
    end
    |> case do
      {:ok, ats} ->
        ats
        |> Enum.filter(&OAuth2TokenManager.token_valid?/1)
        |> Enum.filter(fn {_at, _token_type, at_metadata, _updated_at} ->
          if requested_scope_or_nil do
            Enum.sort(requested_scope_or_nil) == Enum.sort(at_metadata["scope"] || [])
          else
            true
          end
        end)
        |> case do
          [{at, token_type, _at_metadata, _updated_at} | _] ->
            {:ok, {at, token_type}}

          _ ->
            get_new_at(iss, sub_or_cc, client_conf, requested_scope_or_nil, opts)
        end

      {:error, _} = error ->
        error
    end
  end

  defp get_new_at(iss, sub_or_cc, client_conf, requested_scope, opts) do
    RefreshToken.request_access_token(iss, sub_or_cc, client_conf, requested_scope, opts)
    |> case do
      {:ok, {at, token_type, _at_metadata}} ->
        {:ok, {at, token_type}}

      {:error, _} ->
        {:error, %NoSuitableAccessTokenFoundError{}}
    end
  end

  @doc """
  Deletes an access token

  The access token is deleted in the local token data base. If the `:revoke_on_delete` is set,
  an attempt is made to revoke it on the server (but there is no way to know whether it was
  successful or not).
  """
  @spec delete(
    OAuth2TokenManager.access_token(),
    OAuth2TokenManager.issuer(),
    OAuth2TokenManager.client_config(),
    OAuth2TokenManager.opts()
  ) :: :ok | {:error, Exception.t()}
  def delete(at, iss, client_conf, opts \\ []) do
    opts = OAuth2TokenManager.opts_set_default(opts)

    if opts[:revoke_on_delete] do
      Task.start(fn -> revoke(at, iss, client_conf, opts) end)
    end

    Store.delete_access_token(at)
  end

  @doc """
  Deletes all access tokens related to a subject or a client (in the client credentials flow)
  """
  @spec delete_all(
    OAuth2TokenManager.issuer(),
    OAuth2TokenManager.subject() | :client_credentials,
    OAuth2TokenManager.client_config(),
    OAuth2TokenManager.opts()
  ) :: :ok | {:error, Exception.t() | [Exception.t()]}
  def delete_all(iss, sub_or_cc, client_conf, opts \\ []) do
    opts = OAuth2TokenManager.opts_set_default(opts)

    case sub_or_cc do
      <<_::binary>> = sub ->
        Store.get_access_tokens_for_subject(iss, sub)

      :client_credentials ->
        Store.get_access_tokens_client_credentials(iss, client_conf["client_id"])
    end
    |> case do
      {:ok, ats} ->
        for {at, _token_type, _at_metadata, _updated_at} <- ats do
          Task.async(__MODULE__, :delete, [at, client_conf, opts])
        end
        |> Enum.map(&(Task.await(&1)))
        |> Enum.reject(fn ret_val -> ret_val == :ok end)
        |> case do
          [] ->
            :ok

          error_list ->
            {:error, error_list}
        end

      {:error, _} = error ->
        error
    end
  end

  @doc """
  Revokes an access token on the authorization server

  It does not delete the access token locally. To do so, refer to `delete/4`
  """
  @spec revoke(
    OAuth2TokenManager.access_token(),
    OAuth2TokenManager.issuer(),
    OAuth2TokenManager.client_config(),
    OAuth2TokenManager.opts()
  ) :: :ok | {:error, Exception.t()}
  def revoke(at, iss, client_conf, opts \\ []) do
    opts = OAuth2TokenManager.opts_set_default(opts)

    with {:ok, revoke_url} <- Endpoint.url(iss, :revocation, opts),
         {:ok, client} <- Endpoint.http_client(iss, :revocation, client_conf, opts) do
      body = %{
        token: at,
        token_type_hint: "access_token"
      }

      case Tesla.post(client, revoke_url, body) do
        {:ok, %Tesla.Env{status: 200}} ->
          :ok

        {:ok, %Tesla.Env{status: status}} ->
          {:error, %HTTPStatusError{endpoint: :revocation, status: status}}

        {:error, reason} ->
          {:error, %HTTPRequestError{endpoint: :revocation, reason: reason}}
      end
    end
  end

  defp now, do: System.system_time(:second)

  defp hash(at), do: :crypto.hash(:sha256, at)

  defp scope_param_to_list(%{"scope" => scope} = at_metadata) when is_binary(scope) do
    scope = scope |> OAuth2Utils.Scope.Set.from_scope_param!() |> OAuth2Utils.Scope.Set.to_list()

    {:ok, Map.put(at_metadata, "scope", scope)}
  rescue
    e ->
      {:error, e}
  end

  defp scope_param_to_list(at_metadata) do
    {:ok, at_metadata}
  end
end
