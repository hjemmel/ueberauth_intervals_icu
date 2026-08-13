# Überauth intervals.icu

> An [Ueberauth](https://github.com/ueberauth/ueberauth) strategy for authenticating athletes with [intervals.icu](https://intervals.icu).

Implements the OAuth flow described in the [intervals.icu OAuth support thread](https://forum.intervals.icu/t/intervals-icu-oauth-support/2759).

## Installation

```elixir
def deps do
  [
    {:ueberauth_intervals_icu, "~> 0.1.0"}
  ]
end
```

## Registering your application

1. Go to <https://intervals.icu/settings> and create an application to get a **client id** and **client secret**.
2. Register your callback URL **in full**. intervals.icu does *not* support wildcards in redirect URIs, despite what some documentation suggests, so `https://app.example.com/*` will not work. Register every callback URL you use, including your development one.

## Configuration

```elixir
config :ueberauth, Ueberauth,
  providers: [
    intervals_icu: {Ueberauth.Strategy.IntervalsIcu, []}
  ]

config :ueberauth, Ueberauth.Strategy.IntervalsIcu.OAuth,
  client_id: System.get_env("INTERVALS_ICU_CLIENT_ID"),
  client_secret: System.get_env("INTERVALS_ICU_CLIENT_SECRET")
```

Add the routes:

```elixir
scope "/auth", MyAppWeb do
  pipe_through :browser

  get "/:provider", AuthController, :request
  get "/:provider/callback", AuthController, :callback
end
```

And a controller:

```elixir
defmodule MyAppWeb.AuthController do
  use MyAppWeb, :controller

  plug Ueberauth

  def callback(%{assigns: %{ueberauth_failure: %{errors: errors}}} = conn, _params) do
    conn
    |> put_flash(:error, Enum.map_join(errors, ", ", & &1.message))
    |> redirect(to: ~p"/")
  end

  def callback(%{assigns: %{ueberauth_auth: auth}} = conn, _params) do
    # auth.uid                    => "2049151"
    # auth.info.name              => "David (intervals.icu)"
    # auth.credentials.token      => the access token, store this
    # auth.credentials.scopes     => ["ACTIVITY:READ", "WELLNESS:READ"]
    # auth.extra.raw_info.athlete => the full athlete payload

    conn
    |> put_session(:athlete_id, auth.uid)
    |> put_session(:intervals_icu_token, auth.credentials.token)
    |> redirect(to: ~p"/")
  end
end
```

## Without Phoenix

Phoenix already does all of this for you. In a plain `Plug.Router` pipeline, two plugs must run **before** `plug Ueberauth`:

```elixir
plug :fetch_session       # Ueberauth's CSRF check calls fetch_session/1
plug :fetch_query_params  # ...and reads conn.params["state"]
plug Ueberauth
```

Both are required by Ueberauth itself, in `Ueberauth.Strategy.run_callback/2`, which runs before this strategy is reached. Leave either out and the callback raises `ArgumentError` instead of failing cleanly. Swap `:fetch_query_params` for `Plug.Parsers` if you accept POST callbacks.

The cookie session store also needs `conn.secret_key_base` set.

[`examples/oauth_demo.exs`](examples/oauth_demo.exs) is a complete, runnable pipeline — a single file you can point at a real intervals.icu application to check the whole flow end to end:

```sh
export INTERVALS_ICU_CLIENT_ID=... INTERVALS_ICU_CLIENT_SECRET=...
elixir examples/oauth_demo.exs
```

It prints the raw athlete payload and lists any keys the strategy does not map, which is the quickest way to see what intervals.icu actually returns for your account.

## Scopes

intervals.icu joins scopes with **commas**, not the spaces used by most OAuth 2.0 providers:

```elixir
providers: [
  intervals_icu: {Ueberauth.Strategy.IntervalsIcu, [default_scope: "ACTIVITY:READ,WELLNESS:WRITE"]}
]
```

Each scope takes a `:READ` or `:WRITE` suffix:

| Scope | Covers |
|---|---|
| `ACTIVITY` | Activities, intervals, streams |
| `WELLNESS` | Wellness records: weight, HRV, resting HR, sleep |
| `CALENDAR` | Planned workouts and calendar events |
| `CHATS` | Messages |
| `LIBRARY` | Workout and plan library |
| `SETTINGS` | Athlete profile and sport settings |

The default is `"ACTIVITY:READ,WELLNESS:READ,SETTINGS:READ"`.

`SETTINGS:READ` is in there because `:fetch_athlete` defaults to `true` and `/api/v1/athlete/0` requires it. If you override `:default_scope`, either keep `SETTINGS:READ` or set `fetch_athlete: false` — see [below](#the-athlete-fetch-and-when-to-turn-it-off).

You can also request scopes per request, which overrides the configured default:

```
/auth/intervals_icu?scope=CALENDAR:WRITE
```

> **Note:** an `ATHLETES` scope exists but does not work with bearer tokens, where it returns `403`. It only works with API keys.

## Tokens do not expire, and there are no refresh tokens

This is the biggest way intervals.icu departs from a typical OAuth 2.0 provider, and it shapes how you should store credentials.

- There is **no refresh token** and **no expiry**. `auth.credentials` always comes back with `refresh_token: nil`, `expires: false` and `expires_at: nil`.
- Store the access token and use it until it stops working. There is no refresh cycle to implement.
- To recover from a rejected token, send the athlete through the flow again.
- An athlete may hold several tokens for your app, one per authorisation. The most recently granted scopes apply to all of them.

To revoke a token:

```
DELETE https://intervals.icu/api/v1/disconnect-app
Authorization: Bearer <token>
```

## Calling the API

Use athlete id `0` to mean "the athlete this token belongs to":

```elixir
Req.get!("https://intervals.icu/api/v1/athlete/0/activities",
  auth: {:bearer, token},
  params: [oldest: "2026-01-01", newest: "2026-08-12"]
)
```

An OAuth token only ever grants access to the authorising athlete's own data. Coaches cannot reach their athletes' data through a single connection, so each athlete has to authorise your app separately.

## The athlete fetch, and when to turn it off

After exchanging the code, the strategy calls `/api/v1/athlete/0` to build a fuller `Ueberauth.Auth.Info`, the way most Ueberauth strategies do.

**That endpoint requires `SETTINGS:READ`** — verified against the live service, which answers `403` without it. That is why the default scope includes it.

### When the athlete declines

The consent screen has a checkbox per permission, so an athlete can grant activities and wellness while declining settings. When that happens the athlete endpoint answers `403`, and rather than failing a login over an optional profile lookup, the strategy **falls back to the id and name from the token response** and logs a warning.

Authentication still succeeds, but `info` carries only `name`, with `email` and the rest `nil`. Write your callback accordingly — `uid` is always present, anything beyond `name` is best-effort:

```elixir
def callback(%{assigns: %{ueberauth_auth: auth}} = conn, _params) do
  # auth.uid       => always present
  # auth.info.name => always present
  # auth.info.email => nil if the athlete declined SETTINGS
end
```

If you override `:default_scope`, either keep `SETTINGS:READ` in it:

```elixir
providers: [
  intervals_icu: {Ueberauth.Strategy.IntervalsIcu, [default_scope: "ACTIVITY:READ,SETTINGS:READ"]}
]
```

or skip the call entirely:

```elixir
providers: [
  intervals_icu: {Ueberauth.Strategy.IntervalsIcu, [fetch_athlete: false]}
]
```

With `fetch_athlete: false` no extra request is made, and the auth struct is built from the athlete map already present in the token response. You still get `uid` and `name`, but not `email` or the other profile fields — and the athlete is not asked to grant access to their settings, which keeps the consent screen narrower.

Note that `/api/v1/athlete/0` returns roughly **160 fields** — the athlete's whole settings object, including sync state for Garmin, Strava, Wahoo, Zwift and the rest. It all arrives in `extra.raw_info.athlete`, so take the fields you need rather than persisting the struct wholesale.

## Options

| Option | Default | Purpose |
|---|---|---|
| `:default_scope` | `"ACTIVITY:READ,WELLNESS:READ,SETTINGS:READ"` | Scopes requested when no `scope` parameter is given |
| `:fetch_athlete` | `true` | Whether to call the athlete endpoint after the token exchange |
| `:userinfo_endpoint` | `"/api/v1/athlete/0"` | Endpoint used when `:fetch_athlete` is true |
| `:uid_field` | `:id` | Which athlete field becomes `auth.uid` |
| `:oauth2_module` | `Ueberauth.Strategy.IntervalsIcu.OAuth` | Module implementing the OAuth calls |

## Customising HTTP behaviour

Requests go through [Req](https://github.com/wojtekmach/req). Anything under `:req_options` is merged into every request and overrides this library's own defaults:

```elixir
config :ueberauth, Ueberauth.Strategy.IntervalsIcu.OAuth,
  client_id: System.get_env("INTERVALS_ICU_CLIENT_ID"),
  client_secret: System.get_env("INTERVALS_ICU_CLIENT_SECRET"),
  req_options: [receive_timeout: 10_000]
```

**Retries are off by default.** Req would otherwise retry transient failures with backoff, which is the wrong trade-off during an OAuth callback: the athlete is waiting on a redirect, so seconds of backoff before an inevitable failure is worse than failing fast. The authorization code is also only valid for **two minutes**, so a long retry chain can consume the window it is meant to protect. Opt back in with `req_options: [retry: :safe_transient]`.

## Error keys

Failures arrive as `conn.assigns.ueberauth_failure.errors`, each with a `message_key`:

| Key | Meaning |
|---|---|
| `access_denied` | The athlete declined (any `?error=` value is passed through under its own key) |
| `missing_code` | The callback carried neither a code nor an error |
| `token_error` | The token endpoint returned a non-200, most often an expired code |
| `invalid_token_response` | The token endpoint returned 200 but no access token |
| `token` | The athlete endpoint returned `401` |
| `athlete_error` | The athlete endpoint returned another error status |
| `invalid_athlete_response` | The athlete endpoint returned a success status but not a JSON object |
| `network_error` | The request never completed |
| `csrf_attack` | Ueberauth's own state mismatch check |

## License

MIT. See [LICENSE](LICENSE).
