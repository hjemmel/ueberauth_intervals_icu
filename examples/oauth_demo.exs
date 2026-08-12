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

# Set INTERVALS_ICU_FETCH_ATHLETE=false to skip the athlete request, which is
# useful when a grant lacks SETTINGS:READ: login still succeeds and the probe
# below can then show which endpoints that narrower token can reach.
fetch_athlete? = System.get_env("INTERVALS_ICU_FETCH_ATHLETE") != "false"

default_scope =
  System.get_env("INTERVALS_ICU_SCOPE", "ACTIVITY:READ,WELLNESS:READ,SETTINGS:READ")

Application.put_env(:ueberauth, Ueberauth,
  providers: [
    intervals_icu:
      {Ueberauth.Strategy.IntervalsIcu,
       [default_scope: default_scope, fetch_athlete: fetch_athlete?]}
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
      <a href="/auth/intervals_icu?scope=ACTIVITY:READ">narrower scope, without SETTINGS:READ</a>
      &mdash; for comparing which endpoints a token can reach.
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
    # Requested vs granted matters: if SETTINGS:READ was asked for but is
    # missing here, intervals.icu declined to grant it, which is a different
    # problem from the endpoint rejecting a token that does carry it.
    IO.puts("requested:   #{requested_scope()}")
    IO.puts("granted:     #{Enum.join(auth.credentials.scopes, ",")}")
    IO.puts("expires:     #{inspect(auth.credentials.expires)}")
    IO.puts("refresh:     #{inspect(auth.credentials.refresh_token)}")
    IO.puts("\n--- info (what the strategy mapped) ---")
    IO.inspect(auth.info, limit: :infinity)

    # The athlete payload runs to 160+ keys and includes third-party account
    # ids and sync state, so print key *names* in full but values only for the
    # identity fields info/1 might reasonably map. Nothing here should be
    # sensitive enough to worry about pasting into an issue.
    athlete = auth.extra.raw_info.athlete

    IO.puts("\n--- athlete keys (names only, #{map_size(athlete)} total) ---")

    athlete
    |> Map.keys()
    |> Enum.sort()
    |> Enum.chunk_every(4)
    |> Enum.each(fn row ->
      IO.puts("  " <> Enum.map_join(row, "", &String.pad_trailing(&1, 34)))
    end)

    IO.puts("\n--- identity-ish fields, with values ---")

    identity_pattern =
      # ^id$ rather than id$, so third-party account ids such as
      # concept2_user_id stay out of output meant for pasting into an issue.
      ~r/^(id|.*name|email|city|state|country|sex|gender|locale|timezone|time_zone|.*profile.*|avatar|image|photo|picture|bio)$/i

    athlete
    |> Enum.filter(fn {key, value} ->
      Regex.match?(identity_pattern, key) and (is_binary(value) or is_number(value)) and
        value != ""
    end)
    |> Enum.sort()
    |> Enum.each(fn {key, value} ->
      IO.puts("  " <> String.pad_trailing(key, 26) <> inspect(value))
    end)

    probe(auth)

    unmapped =
      athlete
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

  # Asks intervals.icu directly what this token can reach. The activities and
  # wellness endpoints act as controls: if they succeed while the athlete
  # endpoint 403s, the token is fine and that endpoint is specifically
  # restricted, rather than the grant being wrong.
  defp probe(auth) do
    alias Ueberauth.Strategy.IntervalsIcu.OAuth

    token = auth.extra.raw_info.token
    id = auth.uid || "0"
    today = Date.utc_today()
    range = "oldest=#{Date.add(today, -7)}&newest=#{today}"

    paths = [
      {"athlete (id 0)", "/api/v1/athlete/0"},
      {"athlete (real id)", "/api/v1/athlete/#{id}"},
      {"athlete profile", "/api/v1/athlete/0/profile"},
      {"sport settings", "/api/v1/athlete/0/sport-settings"},
      {"activities  [control: ACTIVITY:READ]", "/api/v1/athlete/0/activities?#{range}"},
      {"wellness    [control: WELLNESS:READ]", "/api/v1/athlete/0/wellness?#{range}"}
    ]

    IO.puts("\n--- endpoint probe (what this bearer token can actually reach) ---")

    Enum.each(paths, fn {label, path} ->
      result =
        case OAuth.get(token, path) do
          {:ok, %Req.Response{status: status, body: body}} ->
            "#{status}  #{summarise(body)}"

          {:error, exception} ->
            "ERR  #{Exception.message(exception)}"
        end

      IO.puts(String.pad_trailing(label, 40) <> result)
    end)

    IO.puts("""

    To revoke this grant:
        curl -X DELETE https://intervals.icu/api/v1/disconnect-app \\
          -H 'authorization: Bearer #{token.access_token}'
    """)
  end

  defp requested_scope do
    {_strategy, opts} = Application.get_env(:ueberauth, Ueberauth)[:providers][:intervals_icu]
    Keyword.get(opts, :default_scope, "(none)")
  end

  defp summarise(body) when is_map(body) do
    keys = body |> Map.keys() |> Enum.sort() |> Enum.take(12)
    "map with #{map_size(body)} keys: #{Enum.join(keys, ", ")}"
  end

  defp summarise(body) when is_list(body), do: "list of #{length(body)}"

  defp summarise(body) when is_binary(body),
    do: body |> String.replace(~r/\s+/, " ") |> String.slice(0, 160)

  defp summarise(body), do: inspect(body, limit: 5)

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
