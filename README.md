# OAuth2TokenManager

Manages OAuth2 tokens and OpenID Connect claims and ID tokens

## Installation

```elixir
def deps do
  [
    {:oauth2_token_manager, "~> 0.2"},
    {:hackney, "~> 1.0"}
  ]
end
```


The hackney dependency is used as the default adapter for Tesla. Another one can be used
instead (see
[https://github.com/teamon/tesla#adapters](https://github.com/teamon/tesla#adapters)) and then
has to be configured in your `config.exs`:

```elixir
config :tesla, adapter: Tesla.Adapter.AnotherOne
```

## Options

- `:auto_introspect`: if set to `true`, access and refresh tokens are automatically inspected
when they are registered, so as to gather additional useful information about them. The
authorization server may not be configured to allow a client to inspect its own tokens.
Defaults to `true`
- `:min_introspect_interval`: the minimum time interval in seconds to introspect a token on
the authorization server. Defaults to `30`
- `:min_userinfo_refresh_interval`: the minimum time interval in seconds to request the
userinfo endpoint of the authorization server when requesting claims. Defaults to `30`
- `:oauth2_metadata_updater_opts`: options pased to `Oauth2MetadataUpdater`
- `:revoke_on_delete`: when set to `true`, the calls to
`OAuth2TokenManager.AccessToken.delete/4` and `OAuth2TokenManager.RefreshToken.delete/4`
automatically trigger token revocation on the authorization server. Defaults to `true`
- `:server_metadata`: additional server metadata that takes precedence over that which is
returned from the autorization server
- `:tesla_middlewares`: Tesla middlewares added to requests
- `:tesla_auth_middleware_opts`: options added to the Tesla authentication middleware
selected for client authentication. See also `TeslaOAuth2ClientAuth`

## Client configuration

Client configuration is passed as a parameter to some functions. It must contain at least:
- `"client_id"`: the client id of the client
- `"client_secret"` for use with the client secret basic authentication scheme. The client
authentication scheme is determined by the `"token_endpoint_auth_method"` and defaults to
`"client_secret_basic"` if not set. This is used on the following endpoints:
  - `"token_endpoint"`
  - `"introspection_endpoint"`
  - `"revocation_endpoint"`

When not using the defaults, the client might also have the following configuration fields set:
- `"token_endpoint_auth_method"`
- `"userinfo_signed_response_alg"`
- `"userinfo_encrypted_response_alg"`
- `"userinfo_encrypted_response_enc"`
- `"jwks"`
- `"jwks_uri"`

## Environment options

- `OAuth2TokenManager.Store`: the token store implementation. Defaults to
`OAuth2TokenManager.Store.Local`
- `:tesla_middlewares`: allows adding Tesla middlewares for all request. Example:

```elixir
config :oauth2_token_manager, :tesla_middlewares, [Tesla.Middleware.Logger]
```

## Examples

```elixir
iex>  cc
%{"client_id" => "client1", "client_secret" => "clientpassword1"}

iex>  OAuth2TokenManager.AccessToken.get("https://repentant-brief-fishingcat.gigalixirapp.com", "cThpjg2-HzfS_7fvNkCYeEUBkCUpmKFSjzb6iebl5TU", cc, nil)
{:ok, {"0mUB13mvdDkrsUECnMhK-EGKvL0", "bearer"}}

iex>  OAuth2TokenManager.AccessToken.introspect("0mUB13mvdDkrsUECnMhK-EGKvL0", "https://repentant-brief-fishingcat.gigalixirapp.com", cc)              
{:ok,
 %{
   "active" => true,
   "client_id" => "client1",
   "exp" => 1590345951,
   "iat" => 1590345771,
   "iss" => "https://repentant-brief-fishingcat.gigalixirapp.com",
   "scope" => ["interbank_transfer", "openid", "read_account_information",
    "read_balance"],
   "sub" => "cThpjg2-HzfS_7fvNkCYeEUBkCUpmKFSjzb6iebl5TU"
 }}

iex>  OAuth2TokenManager.AccessToken.get("https://repentant-brief-fishingcat.gigalixirapp.com", "cThpjg2-HzfS_7fvNkCYeEUBkCUpmKFSjzb6iebl5TU", cc, ["read_balance", "read_account_information"])
{:ok, {"4kWo-XDBXzCgwgndK7UTbQE_O6Y", "bearer"}}

iex>  OAuth2TokenManager.AccessToken.introspect("4kWo-XDBXzCgwgndK7UTbQE_O6Y", "https://repentant-brief-fishingcat.gigalixirapp.com", cc)                                                       
{:ok,
 %{
   "active" => true,
   "client_id" => "client1",
   "exp" => 1590346428,
   "iat" => 1590345828,
   "iss" => "https://repentant-brief-fishingcat.gigalixirapp.com",
   "scope" => ["read_account_information", "read_balance"],
   "sub" => "cThpjg2-HzfS_7fvNkCYeEUBkCUpmKFSjzb6iebl5TU"
 }}

iex> OAuth2TokenManager.Claims.get_claims("https://repentant-brief-fishingcat.gigalixirapp.com", "cThpjg2-HzfS_7fvNkCYeEUBkCUpmKFSjzb6iebl5TU", cc)
{:ok, %{"sub" => "cThpjg2-HzfS_7fvNkCYeEUBkCUpmKFSjzb6iebl5TU"}}

iex> OAuth2TokenManager.Claims.get_id_token("https://repentant-brief-fishingcat.gigalixirapp.com", "cThpjg2-HzfS_7fvNkCYeEUBkCUpmKFSjzb6iebl5TU")    
{:ok,
 "eyJhbGciOiJSUzI1NiJ9.eyJhY3IiOiIxLWZhY3RvciIsImFtciI6WyJwd2QiXSwiYXVkIjoiY2xpZW50MSIsImF1dGhfdGltZSI6MTU5MDM0NTM2NSwiZXhwIjoxNTkwMzQ1ODMxLCJpYXQiOjE1OTAzNDU3NzEsImlzcyI6Imh0dHBzOi8vcmVwZW50YW50LWJyaWVmLWZpc2hpbmdjYXQuZ2lnYWxpeGlyYXBwLmNvbSIsInN1YiI6ImNUaHBqZzItSHpmU183ZnZOa0NZZUVVQmtDVXBtS0ZTanpiNmllYmw1VFUifQ.mT3fXJUEeB3nqQDkl7B4RmNo9aQG1xldVw2xBO9gF1e1tew3H3XH_lyzzAcubK47sQDQzSOC6CIMqsFsi2Dr12_62y_QYjo8T3_Pi3TS9RLJUKJQb4_AU1cIbuCCG7iCxBWLHuPGspc_gJrDg_kYskVhnz-0j9cyRBCL1wycuVDAOkRxMAwvnFDUtY57aQWXUknUwIQn4cOpV1CbpT2cLZFo-7EAiukq8GeHmIeYZASctFQZVQ8krwbg3MwknAZ-xfmZ7kT8gobxCexVO8XUZrB_1ht74mynYN1S9ZJT-_ut7dDU621bI-5btUysBTlBhtrvt4mBiOdbDNV8V6Guqw"}

iex> OAuth2TokenManager.AccessToken.delete("4kWo-XDBXzCgwgndK7UTbQE_O6Y", "https://repentant-brief-fishingcat.gigalixirapp.com", cc)
:ok
```
