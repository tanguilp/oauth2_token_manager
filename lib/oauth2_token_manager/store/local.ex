defmodule OAuth2TokenManager.Store.Local do
  @default_cleanup_interval 15

  @moduledoc """
  Simple token store using ETS and DETS

  Access tokens are stored in an ETS, since they can easily be renewed with an access
  token. Refresh tokens and claims are stored in DETS.

  This implementation is probably not suited for production, firstly because it's not
  distributed.

  Since the ETS table must be owned by a process and a cleanup process must be
  implemented to delete expired tokens, this implementation must be started under a
  supervision tree. It implements the `child_spec/1` and `start_link/1` functions (from
  `GenServer`).

  The DETS read and write in the following tables:
  - `"Elixir.OAuth2TokenManager.Store.Local.RefreshToken"` for refresh tokens
  - `"Elixir.OAuth2TokenManager.Store.Local.Claims"` for claims and ID tokens

  ## Options

  - `:cleanup_interval`: the interval between cleanups of the underlying ETS and DETS table in
  seconds. Defaults to #{@default_cleanup_interval}

  ## Starting this implementation

  In your `MyApp.Application` module, add:

      children = [
        OAuth2TokenManager.Store.Local
      ]

  or

      children = [
        {OAuth2TokenManager.Store.Local, cleanup_interval: 30}
      ]
  """

  @behaviour OAuth2TokenManager.Store

  use GenServer

  alias OAuth2TokenManager.Store

  defmodule InsertError do
    defexception [:reason]

    @impl true
    def message(%{reason: reason}), do: "insert failed with reason: #{inspect(reason)}"
  end

  defmodule MultipleResultsError do
    defexception message: "illegal return of multiples entries"
  end

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl GenServer
  def init(opts) do
    :dets.open_file(rt_tab(), [])
    :ets.new(at_tab(), [:public, :named_table, {:read_concurrency, true}])
    :dets.open_file(claim_tab(), [])

    schedule_cleanup(opts)

    {:ok, opts}
  end

  @impl GenServer
  def handle_info(:cleanup, state) do
    cleanup_access_tokens()
    cleanup_refresh_tokens()

    schedule_cleanup(state)

    {:noreply, state}
  end

  defp cleanup_access_tokens() do
    match_spec = [
      {
        {:_, :_, :_, %{"exp" => :"$1"}},
        [{:<, :"$1", now()}],
        [:"$1"]
      }
    ]

    :ets.select_delete(at_tab(), match_spec)
  end

  defp cleanup_refresh_tokens() do
    match_spec = [
      {
        {:_, :_, %{"exp" => :"$1"}},
        [{:<, :"$1", now()}],
        [:"$1"]
      }
    ]

    :dets.select_delete(rt_tab(), match_spec)
  end

  @impl Store
  def get_access_token(at) do
    case :ets.lookup(at_tab(), at) do
      [{at, _issuer, token_type, at_metadata, updated_at}] ->
        if OAuth2TokenManager.token_valid?(at_metadata) do
          {:ok, {at, token_type, at_metadata, updated_at}}
        else
          delete_access_token(at)

          {:ok, nil}
        end

      [] ->
        {:ok, nil}

      [_ | _] ->
        {:error, %MultipleResultsError{}}
    end
  end

  @impl Store
  def get_access_tokens_for_subject(iss, sub) do
    match_spec = [
      {
        {:"$1", :"$2", :_, %{"sub" => :"$3"}, :_},
        [{:==, :"$2", iss}, {:==, :"$3", sub}],
        [:"$1"]
      }
    ]

    result =
      :ets.select(at_tab(), match_spec)
      |> Enum.reduce(
        [],
        fn at, acc ->
          case get_access_token(at) do
            {:ok, {^at, token_type, at_metadata, updated_at}} ->
              [{at, token_type, at_metadata, updated_at} | acc]

            _ ->
              acc
          end
        end
      )
      |> Enum.filter(&OAuth2TokenManager.token_valid?/1)

    {:ok, result}
  rescue
    e ->
      {:error, e}
  end

  @impl Store
  def get_access_tokens_client_credentials(iss, client_id) do
    match_spec = [
      {
        {:"$1", :"$2", :_, %{"client_id" => :"$3"}, :_},
        [{:==, :"$2", iss}, {:==, :"$3", client_id}],
        [:"$1"]
      }
    ]

    result =
      :ets.select(at_tab(), match_spec)
      |> Enum.reduce(
        [],
        fn at, acc ->
          case get_access_token(at) do
            {:ok, {^at, _token_type, %{"sub" => _}, _updated_at}} ->
              acc

            {:ok, {^at, token_type, at_metadata, updated_at}} ->
              [{at, token_type, at_metadata, updated_at} | acc]

            _ ->
              acc
          end
        end
      )
      |> Enum.filter(&OAuth2TokenManager.token_valid?/1)

    {:ok, result}
  rescue
    e ->
      {:error, e}
  end

  @impl Store
  def put_access_token(at, token_type, at_metadata, iss) do
    :ets.insert(at_tab(), {at, iss, token_type, at_metadata, now()})

    {:ok, at_metadata}
  rescue
    e ->
      {:error, e}
  end

  @impl Store
  def delete_access_token(at) do
    :ets.delete(at_tab(), at)

    :ok
  rescue
    e ->
      {:error, e}
  end

  @impl Store
  def get_refresh_token(rt) do
    case :dets.lookup(rt_tab(), rt) do
      [{rt, _issuer, rt_metadata, updated_at}] ->
        {:ok, {rt, rt_metadata, updated_at}}

      [] ->
        {:ok, nil}

      [_ | _] ->
        {:error, %MultipleResultsError{}}
    end
  end

  @impl Store
  def get_refresh_tokens_for_subject(iss, sub) do
    match_spec = [
      {
        {:"$1", :"$2", %{"sub" => :"$3"}, :_},
        [{:==, :"$2", iss}, {:==, :"$3", sub}],
        [:"$1"]
      }
    ]

    result =
      :dets.select(rt_tab(), match_spec)
      |> Enum.reduce(
        [],
        fn rt, acc ->
          case get_refresh_token(rt) do
            {:ok, {^rt, rt_metadata, updated_at}} ->
              [{rt, rt_metadata, updated_at} | acc]

            _ ->
              acc
          end
        end
      )
      |> Enum.filter(&OAuth2TokenManager.token_valid?/1)

    {:ok, result}
  rescue
    e ->
      {:error, e}
  end

  @impl Store
  def get_refresh_tokens_client_credentials(iss, client_id) do
    match_spec = [
      {
        {:"$1", :"$2", %{"client_id" => :"$3"}, :_},
        [{:==, :"$2", iss}, {:==, :"$3", client_id}],
        [:"$1"]
      }
    ]

    result =
      :dets.select(rt_tab(), match_spec)
      |> Enum.reduce(
        [],
        fn rt, acc ->
          case get_refresh_token(rt) do
            {:ok, {^rt, %{"sub" => _}, _updated_at}} ->
              acc

            {:ok, {^rt, rt_metadata, updated_at}} ->
              [{rt, rt_metadata, updated_at} | acc]

            _ ->
              acc
          end
        end
      )
      |> Enum.filter(&OAuth2TokenManager.token_valid?/1)

    {:ok, result}
  rescue
    e ->
      {:error, e}
  end

  @impl Store
  def put_refresh_token(rt, rt_metadata, iss) do
    :dets.insert(rt_tab(), {rt, iss, rt_metadata, now()})

    {:ok, rt_metadata}
  rescue
    e ->
      {:error, e}
  end

  @impl Store
  def delete_refresh_token(rt) do
    :dets.delete(rt_tab(), rt)

    :ok
  rescue
    e ->
      {:error, e}
  end

  @impl Store
  def get_claims(iss, sub) do
    case :dets.lookup(claim_tab(), {iss, sub}) do
      [{{_iss, _sub}, _id_token, claims_or_nil, updated_at_or_nil}] ->
        {:ok, {claims_or_nil, updated_at_or_nil}}

      [] ->
        {:ok, nil}

      [_ | _] ->
        {:error, %MultipleResultsError{}}
    end
  end

  @impl Store
  def put_claims(iss, sub, claims) do
    entry =
      case get_id_token(iss, sub) do
        {:ok, <<_::binary>> = id_token} ->
          {{iss, sub}, id_token, claims, now()}

        {:ok, nil} ->
          {{iss, sub}, nil, claims, now()}
      end

    case :dets.insert(claim_tab(), entry) do
      :ok ->
        :ok

      {:error, reason} ->
        {:error, %InsertError{reason: reason}}
    end
  end

  @impl Store
  def get_id_token(iss, sub) do
    case :dets.lookup(claim_tab(), {iss, sub}) do
      [{{_iss, _sub}, id_token_or_nil, _claims_or_nil, _updated_at_or_nil}] ->
        {:ok, id_token_or_nil}

      [] ->
        {:ok, nil}

      [_ | _] ->
        {:error, %MultipleResultsError{}}
    end
  end

  @impl Store
  def put_id_token(iss, sub, id_token) do
    entry =
      case get_claims(iss, sub) do
        {:ok, {claims_or_nil, updated_at_or_nil}} ->
          {{iss, sub}, id_token, claims_or_nil, updated_at_or_nil}

        {:ok, nil} ->
          {{iss, sub}, id_token, nil, nil}
      end

    case :dets.insert(claim_tab(), entry) do
      :ok ->
        :ok

      {:error, reason} ->
        {:error, %InsertError{reason: reason}}
    end
  end

  defp at_tab(), do: Module.concat(__MODULE__, AccessToken)

  defp rt_tab(), do: Module.concat(__MODULE__, RefreshToken) |> :erlang.atom_to_list()

  defp claim_tab(), do: Module.concat(__MODULE__, Claims) |> :erlang.atom_to_list()

  defp now, do: System.system_time(:second)

  defp schedule_cleanup(state) do
    interval = (state[:cleanup_interval] || @default_cleanup_interval) * 1000

    Process.send_after(self(), :cleanup, interval)
  end
end
