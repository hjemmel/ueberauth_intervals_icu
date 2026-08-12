defmodule Ueberauth.Strategy.IntervalsIcu do
  @moduledoc """
  Ueberauth strategy for authenticating athletes with [intervals.icu](https://intervals.icu).

  ## Setup

  Register an application at <https://intervals.icu/settings> to obtain a client
  id and secret, and register your exact callback URL. intervals.icu does **not**
  support wildcards in redirect URIs — every callback URL must be registered in
  full.

  Add the provider to your Ueberauth configuration:

      config :ueberauth, Ueberauth,
        providers: [
          intervals_icu: {Ueberauth.Strategy.IntervalsIcu, [default_scope: "ACTIVITY:READ"]}
        ]

      config :ueberauth, Ueberauth.Strategy.IntervalsIcu.OAuth,
        client_id: System.get_env("INTERVALS_ICU_CLIENT_ID"),
        client_secret: System.get_env("INTERVALS_ICU_CLIENT_SECRET")

  ## Options

    * `:default_scope` — scopes requested when the request phase does not receive
      a `scope` query parameter. Defaults to `"ACTIVITY:READ,WELLNESS:READ"`.

    * `:fetch_athlete` — whether to call the athlete endpoint after the token
      exchange to build a fuller `Ueberauth.Auth.Info`. Defaults to `true`.
      See "Fetching the athlete" below.

    * `:userinfo_endpoint` — the endpoint used when `:fetch_athlete` is true.
      Defaults to `"/api/v1/athlete/0"`. The athlete id `0` always means "the
      athlete this token belongs to".

    * `:uid_field` — which athlete field becomes `Ueberauth.Auth.uid`. Defaults
      to `:id`.

    * `:oauth2_module` — the module implementing the OAuth calls. Defaults to
      `Ueberauth.Strategy.IntervalsIcu.OAuth`.

  ## Scopes

  intervals.icu scopes are `ACTIVITY`, `WELLNESS`, `CALENDAR`, `CHATS`,
  `LIBRARY` and `SETTINGS`, each suffixed with `:READ` or `:WRITE`, and joined
  with **commas** rather than the spaces used by most OAuth 2.0 providers:

      default_scope: "ACTIVITY:READ,WELLNESS:WRITE"

  ## Fetching the athlete

  The token response already contains the athlete's id and name, so this
  strategy can identify the athlete without any further request.

  By default it still calls `:userinfo_endpoint` to populate a richer
  `Ueberauth.Auth.Info`, mirroring how most Ueberauth strategies behave. That
  endpoint may require a scope your application did not request, in which case
  intervals.icu answers `403` and authentication fails.

  If that happens, either request the necessary scope or turn the call off:

      providers: [
        intervals_icu: {Ueberauth.Strategy.IntervalsIcu, [fetch_athlete: false]}
      ]

  With `fetch_athlete: false` no extra request is made and the auth struct is
  built from the athlete map inside the token response — you get `uid` and
  `name`, but not `email` or the other profile fields.

  ## Tokens do not expire, and there are no refresh tokens

  intervals.icu issues no refresh token and no expiry, so
  `Ueberauth.Auth.Credentials` always comes back with `refresh_token: nil`,
  `expires: false` and `expires_at: nil`. Store the access token and use it
  until it stops working; to recover, send the athlete through the flow again.

  A token can be revoked with:

      DELETE https://intervals.icu/api/v1/disconnect-app
      Authorization: Bearer <token>
  """

  use Ueberauth.Strategy,
    default_scope: "ACTIVITY:READ,WELLNESS:READ",
    uid_field: :id,
    fetch_athlete: true,
    userinfo_endpoint: "/api/v1/athlete/0",
    oauth2_module: Ueberauth.Strategy.IntervalsIcu.OAuth

  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra
  alias Ueberauth.Auth.Info
  alias Ueberauth.Strategy.IntervalsIcu.Token

  @doc """
  Redirects the athlete to the intervals.icu authorize endpoint.

  A `scope` query parameter on the request overrides `:default_scope`, letting
  a single provider ask for different scopes per request.
  """
  @impl Ueberauth.Strategy
  def handle_request!(conn) do
    scopes = conn.params["scope"] || option(conn, :default_scope)

    params =
      [scope: scopes]
      |> with_state_param(conn)

    opts = [redirect_uri: callback_url(conn)]

    redirect!(conn, oauth2_module(conn).authorize_url!(params, opts))
  end

  @doc """
  Handles the redirect back from intervals.icu.

  On success the token is exchanged and, unless `:fetch_athlete` is disabled,
  the athlete is fetched. A denial arrives as `?error=access_denied`.
  """
  @impl Ueberauth.Strategy
  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    params = [code: code]
    opts = [redirect_uri: callback_url(conn)]

    case oauth2_module(conn).get_access_token(params, opts) do
      {:ok, token} ->
        fetch_athlete(conn, token)

      {:error, %{key: key, message: message}} ->
        set_errors!(conn, [error(key, message)])
    end
  end

  def handle_callback!(%Plug.Conn{params: %{"error" => error_key}} = conn) do
    description = conn.params["error_description"] || error_key
    set_errors!(conn, [error(error_key, description)])
  end

  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No authorization code received")])
  end

  @doc """
  Removes the data this strategy stored on the connection.
  """
  @impl Ueberauth.Strategy
  def handle_cleanup!(conn) do
    conn
    |> put_private(:intervals_icu_token, nil)
    |> put_private(:intervals_icu_athlete, nil)
  end

  @doc """
  The athlete's unique id, taken from the field named by `:uid_field`.
  """
  @impl Ueberauth.Strategy
  def uid(conn) do
    conn
    |> athlete()
    |> Map.get(to_string(option(conn, :uid_field)))
  end

  @doc """
  The token, its type and its granted scopes.

  `refresh_token`, `expires` and `expires_at` are always `nil`/`false` —
  intervals.icu issues neither refresh tokens nor expiring access tokens.
  """
  @impl Ueberauth.Strategy
  def credentials(conn) do
    token = token(conn)

    %Credentials{
      token: token.access_token,
      token_type: token.token_type,
      refresh_token: nil,
      expires: false,
      expires_at: nil,
      scopes: Token.scopes(token)
    }
  end

  @doc """
  The athlete's profile information.

  Only `:name` is guaranteed — it is present in the token response. The
  remaining fields depend on what the athlete endpoint returns and are `nil`
  when absent. The complete, untouched athlete map is always available via
  `extra/1`.
  """
  @impl Ueberauth.Strategy
  def info(conn) do
    athlete = athlete(conn)

    %Info{
      name: athlete["name"],
      first_name: athlete["firstname"] || athlete["first_name"],
      last_name: athlete["lastname"] || athlete["last_name"],
      nickname: athlete["username"],
      email: athlete["email"],
      image: athlete["profile_medium"] || athlete["profile"] || athlete["avatar"],
      location: location(athlete),
      urls: %{profile: profile_url(athlete)}
    }
  end

  @doc """
  The raw token and athlete payloads, for anything this strategy does not map.
  """
  @impl Ueberauth.Strategy
  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private[:intervals_icu_token],
        athlete: conn.private[:intervals_icu_athlete]
      }
    }
  end

  # -- internals -------------------------------------------------------------

  defp fetch_athlete(conn, token) do
    if option(conn, :fetch_athlete) do
      request_athlete(conn, token)
    else
      put_athlete(conn, token, token.athlete)
    end
  end

  defp request_athlete(conn, token) do
    endpoint = option(conn, :userinfo_endpoint)

    case oauth2_module(conn).get(token, endpoint) do
      {:ok, %Req.Response{status: 401}} ->
        set_errors!(conn, [error("token", "unauthorized")])

      {:ok, %Req.Response{status: 403}} ->
        set_errors!(conn, [
          error(
            "forbidden",
            "intervals.icu refused access to #{endpoint}. The granted scopes " <>
              "(#{Enum.join(Token.scopes(token), ",")}) may not cover it — request " <>
              "SETTINGS:READ, or set `fetch_athlete: false` to build the auth " <>
              "struct from the token response instead."
          )
        ])

      {:ok, %Req.Response{status: status, body: body}} when status in 200..399 and is_map(body) ->
        put_athlete(conn, token, body)

      {:ok, %Req.Response{status: status, body: body}} when status in 200..399 ->
        set_errors!(conn, [
          error(
            "invalid_athlete_response",
            "expected a JSON object from #{endpoint}, got: #{inspect(body)}"
          )
        ])

      {:ok, %Req.Response{status: status}} ->
        set_errors!(conn, [
          error("athlete_error", "intervals.icu returned HTTP #{status} from #{endpoint}")
        ])

      {:error, exception} ->
        set_errors!(conn, [error("network_error", describe_exception(exception))])
    end
  end

  defp put_athlete(conn, token, athlete) do
    conn
    |> put_private(:intervals_icu_token, token)
    |> put_private(:intervals_icu_athlete, athlete || %{})
  end

  defp token(conn), do: conn.private[:intervals_icu_token]

  defp athlete(conn), do: conn.private[:intervals_icu_athlete] || %{}

  defp oauth2_module(conn), do: option(conn, :oauth2_module)

  defp option(conn, key) do
    Keyword.get(options(conn) || [], key, Keyword.get(default_options(), key))
  end

  defp location(athlete) do
    [athlete["city"], athlete["state"], athlete["country"]]
    |> Enum.reject(&(is_nil(&1) or &1 == ""))
    |> Enum.join(", ")
    |> case do
      "" -> nil
      location -> location
    end
  end

  defp profile_url(%{"id" => id}) when not is_nil(id), do: "https://intervals.icu/athlete/#{id}"
  defp profile_url(_athlete), do: nil

  defp describe_exception(exception) when is_exception(exception),
    do: Exception.message(exception)

  defp describe_exception(other), do: inspect(other)
end
