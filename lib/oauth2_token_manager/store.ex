defmodule OAuth2TokenManager.Store do
  @moduledoc """
  Token store behaviour

  There are 3 types of data to store:
  - access tokens
  - refresh tokens
  - claims and ID token
  """
  use Knigge, implementation: Application.get_env(
    :oauth2_token_manager,
    __MODULE__,
    OAuth2TokenManager.Store.Local
  )

  @doc """
  Returns the access token and its metadata

  If the access token doesn't exist, returns `{:ok, nil}` instead. `{:error, e}` is
  returned only in case of error.

  The returned token is expected to be valid. The `OAuth2TokenManager.token_valid?/1` can be
  used to verify it.
  """
  @callback get_access_token(OAuth2TokenManager.access_token()) ::
  {:ok,
    {
      OAuth2TokenManager.access_token(),
      OAuth2TokenManager.token_type(),
      OAuth2TokenManager.token_metadata(),
      updated_at :: non_neg_integer()
    }
  }
  | {:ok, nil}
  | {:error, Exception.t()}

  @doc """
  Returns all the access tokens for a given subject

  An empty list is returned if there are not access tokens for the subject.

  The returned tokens are expected to be valid. The `OAuth2TokenManager.token_valid?/1` can be
  used to verify it.
  """
  @callback get_access_tokens_for_subject(
    OAuth2TokenManager.issuer(),
    OAuth2TokenManager.subject()
  ) ::
  {:ok, [
    {
      OAuth2TokenManager.access_token(),
      OAuth2TokenManager.token_type(),
      OAuth2TokenManager.token_metadata(),
      updated_at :: non_neg_integer()
    }
  ]}
  | {:error, Exception.t()}

  @doc """
  Returns all the access tokens in the client credentials flow for a client

  An empty list is returned if there are not access tokens for the client in the client
  credentials flow.

  The returned tokens are expected to be valid. The `OAuth2TokenManager.token_valid?/1` can be
  used to verify it.
  """
  @callback get_access_tokens_client_credentials(
    OAuth2TokenManager.issuer(),
    OAuth2TokenManager.client_id()
  ) ::
  {:ok, [
    {
      OAuth2TokenManager.access_token(),
      OAuth2TokenManager.token_type(),
      OAuth2TokenManager.token_metadata(),
      updated_at :: non_neg_integer()
    }
  ]}
  | {:error, Exception.t()}

  @doc """
  Saves an access token and its metadata
  """
  @callback put_access_token(
    access_token :: OAuth2TokenManager.access_token(),
    token_type :: OAuth2TokenManager.token_type(),
    access_token_metadata :: OAuth2TokenManager.token_metadata(),
    issuer :: OAuth2TokenManager.issuer()
  ) :: {:ok, OAuth2TokenManager.token_metadata()} | {:error, Exception.t()}

  @doc """
  Deletes an access token
  """
  @callback delete_access_token(OAuth2TokenManager.access_token()) ::
  :ok | {:error, Exception.t()}

  @doc """
  Returns the refresh token and its metadata

  If the refresh token doesn't exist, returns `{:ok, nil}` instead. `{:error, e}` is
  returned only in case of error.

  The returned token is expected to be valid. The `OAuth2TokenManager.token_valid?/1` can be
  used to verify it.
  """
  @callback get_refresh_token(OAuth2TokenManager.refresh_token()) ::
  {:ok,
    {
      OAuth2TokenManager.refresh_token(),
      OAuth2TokenManager.token_metadata(),
      updated_at :: non_neg_integer()
    }
  }
  | {:ok, nil}
  | {:error, Exception.t()}

  @doc """
  Returns all the refresh tokens for a given subject

  An empty list is returned if there are not refresh tokens for the subject.

  The returned tokens are expected to be valid. The `OAuth2TokenManager.token_valid?/1` can be
  used to verify it.
  """
  @callback get_refresh_tokens_for_subject(
    OAuth2TokenManager.issuer(),
    OAuth2TokenManager.subject()
  ) ::
  {:ok,
    {
      OAuth2TokenManager.refresh_token(),
      OAuth2TokenManager.token_metadata(),
      updated_at :: non_neg_integer()
    }
  }
  | {:error, Exception.t()}

  @doc """
  Returns all the refresh tokens in the client credentials flow for a client

  An empty list is returned if there are not refresh tokens for the client in the client
  credentials flow.

  The returned tokens are expected to be valid. The `OAuth2TokenManager.token_valid?/1` can be
  used to verify it.
  """
  @callback get_refresh_tokens_client_credentials(
    OAuth2TokenManager.issuer(),
    OAuth2TokenManager.client_id()
  ) ::
  {:ok,
    {
      OAuth2TokenManager.refresh_token(),
      OAuth2TokenManager.token_metadata(),
      updated_at :: non_neg_integer()
    }
  }
  | {:error, Exception.t()}

  @doc """
  Saves a refresh token and its metadata
  """
  @callback put_refresh_token(
    refresh_token :: OAuth2TokenManager.refresh_token(),
    refresh_token_metadata :: OAuth2TokenManager.token_metadata(),
    issuer :: OAuth2TokenManager.issuer()
  ) :: {:ok, OAuth2TokenManager.token_metadata()} | {:error, Exception.t()}

  @doc """
  Deletes a refresh token
  """
  @callback delete_refresh_token(OAuth2TokenManager.refresh_token()) ::
  :ok | {:error, Exception.t()}

  @doc """
  Returns claims for a subject
  """
  @callback get_claims(OAuth2TokenManager.issuer(), OAuth2TokenManager.subject()) ::
  {:ok, {OAuth2TokenManager.claims() | nil, updated_at :: non_neg_integer() | nil}}
  | {:error, Exception.t()}

  @doc """
  Registers claims for a subject
  """
  @callback put_claims(
    OAuth2TokenManager.issuer(),
    OAuth2TokenManager.subject(),
    OAuth2TokenManager.claims()
  ) :: :ok | {:error, Exception.t()}

  @doc """
  Returns an ID token for the subject

  There is no obligation to save all of the ID tokens. Instead, the most recent one is typically
  preferred
  """
  @callback get_id_token(OAuth2TokenManager.issuer(), OAuth2TokenManager.subject()) ::
  {:ok, OAuth2TokenManager.id_token() | nil}
  | {:error, Exception.t()}

  @doc """
  Saves an ID token for a subject

  There is no obligation to save all of the ID tokens. Instead, the most recent one is typically
  preferred
  """
  @callback put_id_token(
    OAuth2TokenManager.issuer(),
    OAuth2TokenManager.subject(),
    OAuth2TokenManager.id_token()
  ) :: :ok | {:error, Exception.t()}
end
