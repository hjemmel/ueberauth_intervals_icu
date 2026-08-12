defmodule Ueberauth.Strategy.IntervalsIcu.OAuthConfigTest do
  # Not async: these tests mutate the global application environment. ExUnit runs
  # every async module to completion before any sync module starts, so this
  # cannot race with the rest of the suite.
  use ExUnit.Case, async: false

  alias Ueberauth.Strategy.IntervalsIcu.OAuth

  setup do
    original = Application.get_env(:ueberauth, OAuth)
    on_exit(fn -> Application.put_env(:ueberauth, OAuth, original) end)
    :ok
  end

  defp put_config(config), do: Application.put_env(:ueberauth, OAuth, config)

  test "raises a helpful error when no configuration exists at all" do
    Application.delete_env(:ueberauth, OAuth)

    assert_raise ArgumentError, ~r/missing :client_id/, fn -> OAuth.client() end
  end

  test "raises when client_id is missing" do
    put_config(client_secret: "secret")

    assert_raise ArgumentError, ~r/missing :client_id/, fn -> OAuth.client() end
  end

  test "raises when client_secret is missing" do
    put_config(client_id: "id")

    assert_raise ArgumentError, ~r/missing :client_secret/, fn -> OAuth.client() end
  end

  test "raises when credentials are nil, which is what an unset env var yields" do
    put_config(client_id: nil, client_secret: nil)

    assert_raise ArgumentError, ~r/missing :client_id/, fn -> OAuth.client() end
  end

  test "raises when credentials are blank strings" do
    put_config(client_id: "", client_secret: "secret")

    assert_raise ArgumentError, ~r/missing :client_id/, fn -> OAuth.client() end
  end

  test "raises when the configuration is not a keyword list" do
    put_config(%{client_id: "id", client_secret: "secret"})

    assert_raise ArgumentError, ~r/to be a keyword list/, fn -> OAuth.client() end
  end

  test "raises when the configuration is a plain list" do
    put_config(["not", "a", "keyword", "list"])

    assert_raise ArgumentError, ~r/to be a keyword list/, fn -> OAuth.client() end
  end

  test "the error message tells the developer how to fix it" do
    Application.delete_env(:ueberauth, OAuth)

    error = assert_raise ArgumentError, fn -> OAuth.client() end

    assert error.message =~ "config :ueberauth"
    assert error.message =~ "INTERVALS_ICU_CLIENT_ID"
  end

  test "call-site options can satisfy credentials the config lacks" do
    Application.delete_env(:ueberauth, OAuth)

    client = OAuth.client(client_id: "id", client_secret: "secret")

    assert client.client_id == "id"
    assert client.client_secret == "secret"
  end
end
