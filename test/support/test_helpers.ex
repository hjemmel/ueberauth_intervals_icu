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
        "athlete" => %{"id" => "2049151", "name" => "David (intervals.icu)"}
      },
      overrides
    )
  end

  @doc """
  A richer athlete payload of the sort `/api/v1/athlete/0` returns.
  """
  def athlete_response(overrides \\ %{}) do
    Map.merge(
      %{
        "id" => "2049151",
        "name" => "David (intervals.icu)",
        "firstname" => "David",
        "lastname" => "Tinker",
        "email" => "david@example.com",
        "profile_medium" => "https://intervals.icu/avatar/2049151.jpg",
        "city" => "Cape Town",
        "state" => "Western Cape",
        "country" => "South Africa",
        "sex" => "M",
        "timezone" => "Africa/Johannesburg"
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
  """
  def strategy_conn(params \\ %{}, opts \\ []) do
    :get
    |> Plug.Test.conn("/auth/intervals_icu/callback")
    |> Map.put(:params, params)
    |> Plug.Conn.put_private(:ueberauth_request_options, %{
      options: opts,
      callback_url: @callback_url,
      strategy_name: :intervals_icu
    })
  end

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
