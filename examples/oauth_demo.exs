# A single-file, end-to-end check of the intervals.icu OAuth flow.
#
#     export INTERVALS_ICU_CLIENT_ID=...
#     export INTERVALS_ICU_CLIENT_SECRET=...
#     elixir examples/oauth_demo.exs
#
# Then open http://localhost:4000 and click through.
#
# Before it will work, register this exact redirect URI on your intervals.icu
# application at https://intervals.icu/settings:
#
#     http://localhost:4000/auth/intervals_icu/callback
#
# intervals.icu does not support wildcards in redirect URIs, and whether it
# ignores the port for localhost is an open question on the forum, so register
# the URL in full, port included.
#
# By default this runs against the working tree. To check what Hex actually
# serves, swap the dependency below for {:ueberauth_intervals_icu, "~> 0.1.0"}.

Mix.install([
  {:ueberauth_intervals_icu, path: Path.expand("..", __DIR__)},
  {:bandit, "~> 1.5"}
])

client_id =
  System.get_env("INTERVALS_ICU_CLIENT_ID") ||
    raise "set INTERVALS_ICU_CLIENT_ID"

client_secret =
  System.get_env("INTERVALS_ICU_CLIENT_SECRET") ||
    raise "set INTERVALS_ICU_CLIENT_SECRET"

# This must happen before the router module below is defined: `plug Ueberauth`
# calls `Ueberauth.init/1` at compile time, and that reads application config.
Application.put_env(:ueberauth, Ueberauth,
  providers: [
    intervals_icu:
      {Ueberauth.Strategy.IntervalsIcu,
       [default_scope: System.get_env("INTERVALS_ICU_SCOPE", "ACTIVITY:READ,WELLNESS:READ")]}
  ]
)

Application.put_env(:ueberauth, Ueberauth.Strategy.IntervalsIcu.OAuth,
  client_id: client_id,
  client_secret: client_secret
)

defmodule Demo.Router do
  use Plug.Router

  # Ueberauth's CSRF check calls `Plug.Conn.fetch_session/1`, so a session must
  # be configured even though the state itself lives in a plain cookie.
  # Without this the callback raises rather than failing cleanly.
  plug :put_secret_key_base
  plug Plug.Session,
    store: :cookie,
    key: "_intervals_icu_demo",
    signing_salt: "intervals_icu_demo",
    same_site: "Lax"

  plug :fetch_session

  # Required before `plug Ueberauth`: Ueberauth's own CSRF check reads
  # conn.params["state"] in run_callback/2, before it ever delegates to the
  # strategy, and raises if params were never fetched. Phoenix does this for
  # you. Use Plug.Parsers instead if you accept POST callbacks.
  plug :fetch_query_params

  plug Plug.Logger
  plug Ueberauth
  plug :match
  plug :dispatch

  get "/" do
    send_html(conn, """
    <h1>intervals.icu OAuth demo</h1>
    <p><a href="/auth/intervals_icu">Connect with intervals.icu</a> (default scope)</p>
    <p>
      <a href="/auth/intervals_icu?scope=ACTIVITY:READ">without SETTINGS:READ</a>
      &mdash; expected to fail with <code>forbidden</code>, because the athlete
      endpoint requires it. Set <code>fetch_athlete: false</code> to use this
      narrower scope.
    </p>
    """)
  end

  get "/auth/intervals_icu/callback" do
    case conn.assigns do
      %{ueberauth_auth: auth} -> render_success(conn, auth)
      %{ueberauth_failure: failure} -> render_failure(conn, failure)
      _ -> send_html(conn, "<h1>No Ueberauth result</h1><p>Is the provider configured?</p>")
    end
  end

  match _ do
    send_resp(conn, 404, "not found")
  end

  defp render_success(conn, auth) do
    IO.puts("\n=== SUCCESS ===")
    IO.puts("uid:         #{inspect(auth.uid)}")
    IO.puts("token:       #{String.slice(auth.credentials.token, 0, 8)}… (truncated)")
    IO.puts("token_type:  #{inspect(auth.credentials.token_type)}")
    IO.puts("scopes:      #{inspect(auth.credentials.scopes)}")
    IO.puts("expires:     #{inspect(auth.credentials.expires)}")
    IO.puts("refresh:     #{inspect(auth.credentials.refresh_token)}")
    IO.puts("\n--- info (what the strategy mapped) ---")
    IO.inspect(auth.info, limit: :infinity)

    # The point of this demo: the real athlete payload, so the mapping in
    # `info/1` can be checked against what intervals.icu actually returns.
    IO.puts("\n--- raw athlete payload ---")
    IO.inspect(auth.extra.raw_info.athlete, limit: :infinity, printable_limit: :infinity)

    unmapped =
      auth.extra.raw_info.athlete
      |> Map.keys()
      |> Enum.reject(&(&1 in ~w(name firstname first_name lastname last_name username email
                                profile_medium profile avatar city state country id)))
      |> Enum.sort()

    IO.puts("\n--- athlete keys the strategy does not map ---")
    IO.inspect(unmapped, limit: :infinity)

    send_html(conn, """
    <h1>Connected</h1>
    <p>uid: <code>#{escape(auth.uid)}</code></p>
    <p>name: <code>#{escape(auth.info.name)}</code></p>
    <p>scopes: <code>#{escape(Enum.join(auth.credentials.scopes, ", "))}</code></p>
    <p>Full details printed to the console.</p>
    <p><a href="/">start again</a></p>
    """)
  end

  defp render_failure(conn, failure) do
    IO.puts("\n=== FAILURE ===")
    IO.inspect(failure.errors, limit: :infinity)

    items =
      Enum.map_join(failure.errors, "", fn error ->
        "<li><strong>#{escape(error.message_key)}</strong>: #{escape(error.message)}</li>"
      end)

    send_html(conn, "<h1>Authentication failed</h1><ul>#{items}</ul><p><a href=\"/\">retry</a></p>")
  end

  defp send_html(conn, body) do
    conn
    |> put_resp_content_type("text/html")
    |> send_resp(200, "<!doctype html><meta charset=utf-8>" <> body)
  end

  defp escape(nil), do: "(nil)"
  defp escape(value), do: value |> to_string() |> Plug.HTML.html_escape()

  defp put_secret_key_base(conn, _opts) do
    %{conn | secret_key_base: String.duplicate("intervals_icu_demo_secret_", 3)}
  end
end

port = String.to_integer(System.get_env("PORT", "4000"))

IO.puts("""

intervals.icu OAuth demo listening on http://localhost:#{port}

Registered redirect URI must be exactly:
    http://localhost:#{port}/auth/intervals_icu/callback
""")

{:ok, _} = Bandit.start_link(plug: Demo.Router, port: port)
Process.sleep(:infinity)
