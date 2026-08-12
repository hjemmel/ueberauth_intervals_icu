defmodule UeberauthIntervalsIcu.MixProject do
  use Mix.Project

  @version "0.1.1"
  @source_url "https://github.com/hjemmel/ueberauth_intervals_icu"

  def project do
    [
      app: :ueberauth_intervals_icu,
      version: @version,
      elixir: "~> 1.15",
      start_permanent: Mix.env() == :prod,
      elixirc_paths: elixirc_paths(Mix.env()),
      test_coverage: [
        # Test support code is not part of the library's coverage.
        ignore_modules: [Ueberauth.IntervalsIcu.TestHelpers],
        # Actual coverage sits around 95%. The floor is deliberately a little
        # below that: high enough to catch a meaningfully untested addition,
        # loose enough that a small refactor does not fail CI.
        summary: [threshold: 90]
      ],
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs(),
      name: "Ueberauth intervals.icu",
      source_url: @source_url
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:ueberauth, "~> 0.10"},
      {:req, "~> 0.5"},
      {:plug, "~> 1.16"},
      {:ex_doc, "~> 0.34", only: :dev, runtime: false}
    ]
  end

  defp description do
    "An Ueberauth strategy for authenticating athletes with intervals.icu via OAuth."
  end

  defp package do
    [
      licenses: ["MIT"],
      maintainers: ["hjemmel"],
      links: %{
        "GitHub" => @source_url,
        "intervals.icu OAuth spec" =>
          "https://forum.intervals.icu/t/intervals-icu-oauth-support/2759"
      },
      files: ~w(lib mix.exs README.md CHANGELOG.md LICENSE)
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      extras: ["README.md", "CHANGELOG.md", "LICENSE"]
    ]
  end
end
