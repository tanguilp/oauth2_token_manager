defmodule OAuth2TokenManager.HTTPStatusError do
  defexception [:endpoint, :status]

  def message(%{endpoint: endpoint, status: status}),
    do: "the #{endpoint} endpoint responded with status `#{status}`"
end

defmodule OAuth2TokenManager.HTTPRequestError do
  defexception [:endpoint, :reason]

  def message(%{endpoint: endpoint, reason: reason}),
    do: "HTTP request to the #{endpoint} endpoint failed with: #{inspect(reason)}"
end

defmodule OAuth2TokenManager.MissingServerMetadataError do
  defexception [:field]

  def message(%{field: field}), do: "missing `#{field}` from server metadata"
end

defmodule OAuth2TokenManager.MissingClientMetadataError do
  defexception [:field]

  def message(%{field: field}), do: "missing `#{field}` from client metadata"
end

defmodule OAuth2TokenManager.NoSuitableAccessTokenFoundError do
  defexception message: "no suitable access token could be found or retrieved"
end

defmodule OAuth2TokenManager.NoSuitableRefreshTokenFoundError do
  defexception message: "no suitable refresh token could be found or retrieved"
end

defmodule OAuth2TokenManager.UserinfoEndpointInvalidContentTypeError do
  defexception message: "the userinfo endpoint responded with an invalid content type"
end

defmodule OAuth2TokenManager.UserinfoEndpointDecryptionFailureError do
  defexception message: "the userinfo encrypted response could not be decrypted"
end

defmodule OAuth2TokenManager.UserinfoEndpointVerificationFailureError do
  defexception message: "the userinfo signed response could not be verified"
end

defmodule OAuth2TokenManager.IllegalTokenEndpointResponseError do
  defexception message: "illegal response from the token endpoint"
end

defmodule OAuth2TokenManager.InvalidIDTokenRegistrationError do
  defexception message: "attempt to store an invalid ID token, must be a JWS (and NOT a JWE)"
end
