defmodule OAuth2TokenManager.RefreshToken do
  require Logger

  alias OAuth2TokenManager.{
    AccessToken,
    Claims,
    Endpoint,
    HTTPRequestError,
    HTTPStatusError,
    IllegalTokenEndpointResponseError,
    NoSuitableRefreshTokenFoundError,
    Store
  }

  @doc """
  Registers a refresh token
  """
  @spec register(
    OAuth2TokenManager.refresh_token(),
    OAuth2TokenManager.token_metadata(),
    OAuth2TokenManager.issuer(),
    OAuth2TokenManager.client_config(),
    OAuth2TokenManager.opts()
  ) :: {:ok, OAuth2TokenManager.token_metadata()} | {:error, Exception.t()}
  def register(rt, rt_metadata, iss, client_conf, opts \\ []) do
    opts = OAuth2TokenManager.opts_set_default(opts)

    if opts[:auto_introspect] == true or rt_metadata["sub"] == nil do
      with {:ok, rt_metadata} <- introspect(rt, iss, client_conf, opts) do
        Store.put_refresh_token(rt, rt_metadata, iss)
      end
    else
      with {:ok, rt_metadata} <- scope_param_to_list(rt_metadata) do
        Store.put_refresh_token(rt, rt_metadata, iss)
      end
    end
  end

  @doc false
  @spec request_access_token(
    OAuth2TokenManager.issuer(),
    OAuth2TokenManager.subject() | :client_credentials,
    OAuth2TokenManager.client_config(),
    [OAuth2TokenManager.scope()] | nil,
    OAuth2TokenManager.opts()
  ) ::
  {:ok,
    {
      OAuth2TokenManager.access_token(),
      OAuth2TokenManager.token_type(),
      OAuth2TokenManager.token_metadata()
    }
  }
  | {:error, Exception.t()}
  def request_access_token(iss, sub_or_cc, client_conf, scopes_or_nil, opts) do
    opts = OAuth2TokenManager.opts_set_default(opts)

    with {:ok, {rt, rt_metadata}} <- suitable_refresh_token(iss, sub_or_cc, scopes_or_nil),
         {:ok, token_endpoint_url} <- Endpoint.url(iss, :token, opts),
         {:ok, client} <- Endpoint.http_client(iss, :token, client_conf, opts) do
      body = %{
        grant_type: "refresh_token",
        refresh_token: rt,
      }

      body =
        if scopes_or_nil && scopes_or_nil != [] do
          scope =
            scopes_or_nil
            |> OAuth2Utils.Scope.Set.new()
            |> OAuth2Utils.Scope.Set.to_scope_param()

          Map.put(body, "scope", scope)
        else
          body
        end

      case Tesla.post(client, token_endpoint_url, body) do
        {:ok, %Tesla.Env{status: 200, body: body}} ->
          handle_token_endpoint_response(
            body, rt, rt_metadata, iss, client_conf, scopes_or_nil, opts
          )

        {:ok, %Tesla.Env{status: status}} ->
          {:error, %HTTPStatusError{endpoint: :token, status: status}}

        {:error, reason} ->
          {:error, %HTTPRequestError{endpoint: :token, reason: reason}}
      end
    end
  end

  defp suitable_refresh_token(iss, <<_::binary>> = sub, scopes_or_nil) do
    with {:ok, rt_list} <- Store.get_refresh_tokens_for_subject(iss, sub) do
      suitable_rts = Enum.filter(rt_list, fn {_rt, rt_metadata, _updated_at} ->
        refresh_token_has_scopes?(rt_metadata, scopes_or_nil)
      end)

      case suitable_rts do
        [{rt, rt_metadata, _updated_at} | _] ->
          {:ok, {rt, rt_metadata}}

        [] ->
          {:error, %NoSuitableRefreshTokenFoundError{}}
      end
    end
  end

  defp handle_token_endpoint_response(
    %{"access_token" => at, "token_type" => token_type} = endpoint_resp,
    req_rt,
    req_rt_metadata,
    iss,
    client_conf,
    scopes_or_nil,
    opts
  ) do
    with :ok <- save_new_rt(endpoint_resp, req_rt, req_rt_metadata, iss, client_conf, opts),
         :ok <- save_new_id_token(endpoint_resp, iss, client_conf, opts) do
      granted_scopes =
        case endpoint_resp do
          %{"scope" => scope} ->
            scope
            |> OAuth2Utils.Scope.Set.from_scope_param!()
            |> OAuth2Utils.Scope.Set.to_list()

          _ ->
            scopes_or_nil
        end

      at_metadata =
        req_rt_metadata
        |> Map.take(["client_id", "username", "sub", "aud", "iss"])
        |> Map.put("exp", now() + endpoint_resp["expires_in"])
        |> Map.put("scope", granted_scopes)
        |> Enum.reject(fn {_k, v} -> v == nil end)
        |> Enum.into(%{})

      case AccessToken.register(at, token_type, at_metadata, iss, client_conf, opts) do
        {:ok, at_metadata} ->
          {:ok, {at, token_type, at_metadata}}

        {:error, _} = error ->
          error
      end
    end
  rescue
    e ->
      {:error, e}
  end

  defp handle_token_endpoint_response(_, _, _, _, _, _, _) do
    {:error, %IllegalTokenEndpointResponseError{}}
  end

  defp save_new_rt(%{"refresh_token" => rt}, req_rt, req_rt_metadata, iss, client_conf, opts) do
    with :ok <- delete(req_rt, iss, client_conf, opts),
         {:ok, _} <- register(rt, req_rt_metadata, iss, client_conf, opts) do
      :ok
    end
  end

  defp save_new_rt(_, _, _, _, _, _) do
    :ok
  end

  defp save_new_id_token(%{"id_token" => id_token}, iss, client_conf, opts) do
    verification_data = [
      client_id: client_conf["client_id"],
      issuer: iss,
      oauth2_metadata_updater_opts: opts[:oauth2_metadata_updater_opts],
      server_metadata: opts[:server_metadata]
    ]
    |> Enum.reject(fn {_k, v} -> v == nil end)
    |> Enum.into(%{})

    with {:ok, _} <- OIDC.IDToken.verify(id_token, client_conf, verification_data) do
      Claims.register_id_token(iss, id_token)
    end
  end

  defp save_new_id_token(_, _, _, _) do
    :ok
  end

  defp refresh_token_has_scopes?(_, nil) do
    true
  end

  defp refresh_token_has_scopes?(_, []) do
    true
  end

  defp refresh_token_has_scopes?(%{"scope" => scope}, [_ | _] = requested_scopes) do
    rt_scopes = MapSet.new(scope)
    requested_scopes = MapSet.new(requested_scopes)

    MapSet.subset?(requested_scopes, rt_scopes)
  end

  defp refresh_token_has_scopes?(_, [_ | _]) do
    false
  end

  @doc """
  Introspects a refresh token

  A request is performed to the introspection endpoint of the authorization server if saved
  metadata is not fresh (`:min_introspect_interval` option, see `t:OAuth2TokenManager.opts/0`).

  The response is **not** saved. Use `register/5` if you want to do so.
  """
  @spec introspect(
    OAuth2TokenManager.refresh_token(),
    OAuth2TokenManager.issuer(),
    OAuth2TokenManager.client_config(),
    OAuth2TokenManager.opts()
  ) :: {:ok, OAuth2TokenManager.token_metadata()} | {:error, Exception.t()}
  def introspect(rt, iss, client_conf, opts \\ []) do
    opts = OAuth2TokenManager.opts_set_default(opts)

    case Store.get_refresh_token(rt) do
      {:ok, {^rt, rt_metadata, updated_at}} ->
        if now() - updated_at < opts[:min_introspect_interval] do
          {:ok, rt_metadata}
        else
          do_introspect(rt, iss, client_conf, opts)
        end

      {:ok, _} ->
        do_introspect(rt, iss, client_conf, opts)

      {:error, _} = error ->
        error
    end
  end

  defp do_introspect(rt, iss, client_conf, opts) do
    with {:ok, introspect_url} <- Endpoint.url(iss, :introspection, opts),
         {:ok, client} <- Endpoint.http_client(iss, :introspection, client_conf, opts) do
      body = %{
        token: rt,
        token_type_hint: "refresh_token"
      }

      case Tesla.post(client, introspect_url, body) do
        {:ok, %Tesla.Env{status: 200, body: body}} ->
          with {:ok, rt_metadata} <- scope_param_to_list(body) do
            {:ok, rt_metadata}
          end

        {:ok, %Tesla.Env{status: status}} ->
          Logger.warn("Could not introspect refresh token `#{hash(rt)}` (sha256), reason: " <>
            "invalid HTTP status `#{status}`"
          )

          {:error, %HTTPStatusError{endpoint: :introspection, status: status}}

        {:error, reason} ->
          Logger.warn("Could not introspect refresh token `#{hash(rt)}` (sha256), reason: " <>
            "failed HTTP request `#{inspect(reason)}`"
          )

          {:error, %HTTPRequestError{endpoint: :introspection, reason: reason}}
      end
    end
  end

  @doc """
  Deletes a refresh token

  The refresh token is deleted in the local token data base. If the `:revoke_on_delete` is set,
  an attempt is made to revoke it on the server (but there is no way to know whether it was
  successful or not).
  """
  @spec delete(
    OAuth2TokenManager.refresh_token(),
    OAuth2TokenManager.issuer(),
    OAuth2TokenManager.client_config(),
    OAuth2TokenManager.opts()
  ) :: :ok | {:error, Exception.t()}
  def delete(rt, iss, client_conf, opts \\ []) do
    opts = OAuth2TokenManager.opts_set_default(opts)

    if opts[:revoke_on_delete] do
      Task.start(fn -> revoke(rt, iss, client_conf, opts) end)
    end

    Store.delete_refresh_token(rt)
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
        Store.get_refresh_tokens_for_subject(iss, sub)

      :client_credentials ->
        Store.get_refresh_tokens_client_credentials(iss, client_conf["client_id"])
    end
    |> case do
      {:ok, rts} ->
        for {rt, _rt_metadata, _updated_at} <- rts do
          Task.async(__MODULE__, :delete, [rt, client_conf, opts])
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
  Revokes a refresh token

  It does not delete the refresh token locally. To do so, refer to `delete/4`
  """
  @spec revoke(
    OAuth2TokenManager.refresh_token(),
    OAuth2TokenManager.issuer(),
    OAuth2TokenManager.client_config(),
    OAuth2TokenManager.opts()
  ) :: :ok | {:error, Exception.t()}
  def revoke(rt, iss, client_conf, opts \\ []) do
    opts = OAuth2TokenManager.opts_set_default(opts)

    with {:ok, revoke_url} <- Endpoint.url(iss, :revocation, opts),
         {:ok, client} <- Endpoint.http_client(iss, :revocation, client_conf, opts) do
      body = %{
        token: rt,
        token_type_hint: "refresh_token"
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

  defp scope_param_to_list(%{"scope" => scope} = rt_metadata) when is_binary(scope) do
    scope = scope |> OAuth2Utils.Scope.Set.from_scope_param!() |> OAuth2Utils.Scope.Set.to_list()

    {:ok, Map.put(rt_metadata, "scope", scope)}
  rescue
    e ->
      {:error, e}
  end

  defp scope_param_to_list(rt_metadata) do
    {:ok, rt_metadata}
  end
end
