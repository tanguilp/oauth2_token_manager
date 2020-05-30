defmodule OAuth2TokenManagerRefreshTokenTest do
  use ExUnit.Case

  alias OAuth2TokenManager.RefreshToken

  @iss "https://example.org"

  setup_all do
    Tesla.Mock.mock_global(fn
      %{method: :get, url: @iss <> "/.well-known/openid-configuration"} ->
        %Tesla.Env{status: 200, body: %{}}

      %{method: :post, url: @iss <> "/revoke"} ->
        %Tesla.Env{status: 200}
    end)

    [
      client_conf: client_conf(),
      opts: [server_metadata: server_metadata()]
    ]
  end

  describe ".revoke/4" do
    test "revoke a token", %{opts: opts, client_conf: client_conf} do
      rt = "123456"

      assert :ok == RefreshToken.revoke(rt, @iss, client_conf, opts)
    end
  end

  defp server_metadata() do
    %{
      "token_endpoint" => @iss <> "/token",
      "token_endpoint_auth_methods_supported" => ["client_secret_basic"],
      "revocation_endpoint" => @iss <> "/revoke"
    }
  end

  defp client_conf() do
    %{
      "client_id" => "client1",
      "client_secret" => "some secret"
    }
  end
end
