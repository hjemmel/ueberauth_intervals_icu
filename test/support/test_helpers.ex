defmodule Ueberauth.IntervalsIcu.TestHelpers do
  @moduledoc """
  Shared fixtures and helpers for the test suite.

  Every HTTP interaction goes through `Req.Test`, so stubs run in-process and
  the whole suite stays `async: true`.
  """

  alias Ueberauth.Strategy.IntervalsIcu.OAuth
  alias Ueberauth.Strategy.IntervalsIcu.Token

  @callback_url "https://example.com/auth/intervals_icu/callback"

  @doc """
  A token-endpoint response body exactly as documented by intervals.icu.
  """
  def token_response(overrides \\ %{}) do
    Map.merge(
      %{
        "token_type" => "Bearer",
        "access_token" => "d842c1fc25f241e5ae440d09756448a9",
        "scope" => "ACTIVITY:READ,WELLNESS:READ",
        "athlete" => %{"id" => "i123456", "name" => "Test Athlete"}
      },
      overrides
    )
  end

  @doc """
  An athlete payload using the real field names `/api/v1/athlete/0` returns.

  Verified against the live service. The genuine response carries around 160
  keys; this keeps the ones the strategy maps, plus `icu_api_key` because the
  real payload really does include the athlete's API key and the tests need to
  reason about that.

  Note that athlete ids are not numeric: real ones look like `"i123456"`.
  """
  def athlete_response(overrides \\ %{}) do
    Map.merge(
      %{
        "id" => "i123456",
        "name" => "Test Athlete",
        "firstname" => "Test",
        "lastname" => "Athlete",
        "email" => "athlete@example.com",
        "bio" => "Rides bikes",
        "website" => "https://example.com",
        "icu_date_of_birth" => "1985-04-12",
        "profile_medium" =>
          "https://storage.googleapis.com/intervals-icu-images/profile_pics/497f63b3",
        "city" => "Melbourne",
        "state" => "Victoria",
        "country" => "Australia",
        "sex" => "M",
        "locale" => "en",
        "timezone" => "Australia/Melbourne",
        "icu_api_key" => "secret-api-key",
        "icu_friend_invite_token" => "secret-invite-token"
      },
      overrides
    )
  end

  @doc """
  A token struct, without going through the HTTP layer.
  """
  def token(overrides \\ %{}) do
    {:ok, token} = Token.from_response(token_response(overrides))
    token
  end

  @doc """
  The callback URL used throughout the suite.
  """
  def callback_url, do: @callback_url

  @doc """
  Builds a `Plug.Conn` shaped the way Ueberauth hands one to a strategy.

  Ueberauth stores strategy options under `:ueberauth_request_options`, which is
  where `Ueberauth.Strategy.Helpers.options/1` and `callback_url/1` read from.

  Parameters are passed as a real query string and deliberately left
  **unfetched**, because that is how a connection arrives in a plain Plug
  pipeline. Injecting `conn.params` directly would hide whether the strategy
  fetches them itself.
  """
  def strategy_conn(params \\ %{}, opts \\ []) do
    :get
    |> Plug.Test.conn("/auth/intervals_icu/callback" <> query_string(params))
    |> Plug.Conn.put_private(:ueberauth_request_options, %{
      options: opts,
      callback_url: @callback_url,
      strategy_name: :intervals_icu
    })
  end

  defp query_string(params) when map_size(params) == 0, do: ""
  defp query_string(params), do: "?" <> URI.encode_query(params)

  @doc """
  Adds the CSRF state parameter Ueberauth would have generated.
  """
  def with_state(conn, state) do
    Plug.Conn.put_private(conn, :ueberauth_state_param, state)
  end

  @doc """
  Stubs the intervals.icu endpoints.

  Pass `:token` and/or `:athlete` as either a plug function (for full control
  over status and body) or a map, which is sent back as `200 OK` JSON. Any
  request to an unstubbed path fails the test loudly rather than silently
  returning something unexpected.
  """
  def stub_intervals_icu(stubs) do
    Req.Test.stub(OAuth, fn conn ->
      case {conn.method, conn.request_path} do
        {"POST", "/api/oauth/token"} ->
          respond(conn, Keyword.get(stubs, :token), "token endpoint")

        {"GET", _path} ->
          respond(conn, Keyword.get(stubs, :athlete), "athlete endpoint")

        {method, path} ->
          raise "unexpected #{method} #{path} in test"
      end
    end)
  end

  @doc """
  Reads a form-encoded request body inside a stub plug.
  """
  def read_form_body(conn) do
    {:ok, body, conn} = Plug.Conn.read_body(conn)
    {URI.decode_query(body), conn}
  end

  defp respond(_conn, nil, name), do: raise("#{name} was called but not stubbed")
  defp respond(conn, fun, _name) when is_function(fun, 1), do: fun.(conn)
  defp respond(conn, body, _name) when is_map(body), do: Req.Test.json(conn, body)
end
