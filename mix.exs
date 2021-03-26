defmodule OAuth2TokenManager.MixProject do
  use Mix.Project

  def project do
    [
      app: :oauth2_token_manager,
      description: "Manages OAuth2 tokens and OpenID Connect claims and ID tokens",
      version: "0.2.0",
      elixir: "~> 1.9",
      start_permanent: Mix.env() == :prod,
      docs: [
        main: "readme",
        extras: ["README.md"]
      ],
      deps: deps(),
      package: package(),
      source_url: "https://github.com/tanguilp/oauth2_token_manager"
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:dialyxir, "~> 1.0.0-rc.4", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false},
      {:hackney, "~> 1.0", optional: true},
      {:jose_utils, "~> 0.2"},
      {:knigge, "~> 1.4"},
      {:oauth2_metadata_updater, "~> 1.0"},
      {:oauth2_utils, "~> 0.1.0"},
      {:oidc, "~> 0.2"},
      {:tesla_oauth2_client_auth, "~> 0.2.0"}
    ]
  end

  def package() do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/tanguilp/oauth2_token_manager"}
    ]
  end
end
