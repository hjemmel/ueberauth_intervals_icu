defmodule Ueberauth.Strategy.IntervalsIcuTest do
  use ExUnit.Case, async: true

  import Ueberauth.IntervalsIcu.TestHelpers

  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra
  alias Ueberauth.Auth.Info
  alias Ueberauth.Strategy.IntervalsIcu
  alias Ueberauth.Strategy.IntervalsIcu.Token

  defp errors(conn), do: conn.assigns.ueberauth_failure.errors

  defp error_keys(conn), do: Enum.map(errors(conn), & &1.message_key)

  defp location(conn) do
    conn |> Plug.Conn.get_resp_header("location") |> List.first()
  end

  defp query_params(conn) do
    conn |> location() |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()
  end

  # Runs the callback phase end to end and returns the resulting conn.
  defp callback(params, opts \\ []) do
    params
    |> strategy_conn(opts)
    |> IntervalsIcu.handle_callback!()
  end

  describe "default_options/0" do
    test "documents the defaults the strategy ships with" do
      defaults = IntervalsIcu.default_options()

      assert defaults[:default_scope] == "ACTIVITY:READ,WELLNESS:READ,SETTINGS:READ"
      assert defaults[:uid_field] == :id
      assert defaults[:fetch_athlete] == true
      assert defaults[:userinfo_endpoint] == "/api/v1/athlete/0"
      assert defaults[:oauth2_module] == Ueberauth.Strategy.IntervalsIcu.OAuth
    end
  end

  # Regression: both phases used to read conn.params without fetching them.
  # Under Phoenix that works, because params are always fetched by then. In a
  # plain Plug pipeline the request phase raised ArgumentError, and the callback
  # phase silently fell through to "missing_code" because %Plug.Conn.Unfetched{}
  # never matches %{"code" => _}.
  describe "connections whose params have not been fetched" do
    test "the request phase fetches them itself" do
      conn = strategy_conn(%{"scope" => "CALENDAR:READ"})

      assert %Plug.Conn.Unfetched{} = conn.params

      conn = IntervalsIcu.handle_request!(conn)

      assert query_params(conn)["scope"] == "CALENDAR:READ"
    end

    test "the callback phase fetches them itself rather than reporting missing_code" do
      stub_intervals_icu(token: token_response(), athlete: athlete_response())

      conn = strategy_conn(%{"code" => "the-code"})

      assert %Plug.Conn.Unfetched{} = conn.params

      conn = IntervalsIcu.handle_callback!(conn)

      refute Map.has_key?(conn.assigns, :ueberauth_failure)
      assert IntervalsIcu.uid(conn) == "i123456"
    end

    test "a denial is still recognised without fetched params" do
      conn = %{"error" => "access_denied"} |> strategy_conn() |> IntervalsIcu.handle_callback!()

      assert error_keys(conn) == ["access_denied"]
    end
  end

  describe "handle_request!/1" do
    test "redirects to the intervals.icu authorize endpoint" do
      conn = IntervalsIcu.handle_request!(strategy_conn())

      assert conn.status == 302
      assert conn.halted

      assert %URI{scheme: "https", host: "intervals.icu", path: "/oauth/authorize"} =
               conn |> location() |> URI.parse()
    end

    test "requests the default scope when none is given" do
      conn = IntervalsIcu.handle_request!(strategy_conn())

      assert query_params(conn)["scope"] == "ACTIVITY:READ,WELLNESS:READ,SETTINGS:READ"
    end

    # Verified against the live service: /api/v1/athlete/0 returns 403 without
    # SETTINGS:READ, so a default that omits it makes the out-of-the-box
    # configuration fail on first login.
    test "the default scope covers the athlete endpoint that :fetch_athlete uses" do
      defaults = IntervalsIcu.default_options()

      assert defaults[:fetch_athlete] == true
      assert defaults[:default_scope] =~ "SETTINGS:READ"
    end

    test "honours a :default_scope option" do
      conn = IntervalsIcu.handle_request!(strategy_conn(%{}, default_scope: "CALENDAR:WRITE"))

      assert query_params(conn)["scope"] == "CALENDAR:WRITE"
    end

    test "a scope query parameter overrides the configured default" do
      conn =
        %{"scope" => "LIBRARY:READ,CHATS:READ"}
        |> strategy_conn(default_scope: "ACTIVITY:READ")
        |> IntervalsIcu.handle_request!()

      assert query_params(conn)["scope"] == "LIBRARY:READ,CHATS:READ"
    end

    test "sends the callback URL as the redirect_uri" do
      conn = IntervalsIcu.handle_request!(strategy_conn())

      assert query_params(conn)["redirect_uri"] == callback_url()
    end

    test "includes the CSRF state parameter when Ueberauth generated one" do
      conn =
        strategy_conn()
        |> with_state("csrf-state-value")
        |> IntervalsIcu.handle_request!()

      assert query_params(conn)["state"] == "csrf-state-value"
    end

    test "omits state when Ueberauth did not generate one" do
      conn = IntervalsIcu.handle_request!(strategy_conn())

      refute Map.has_key?(query_params(conn), "state")
    end

    test "never puts the client secret in the redirect" do
      conn = IntervalsIcu.handle_request!(strategy_conn())

      refute location(conn) =~ "test_client_secret"
    end
  end

  describe "handle_callback!/1 success" do
    setup do
      stub_intervals_icu(token: token_response(), athlete: athlete_response())
      :ok
    end

    test "stores the token and the fetched athlete on the connection" do
      conn = callback(%{"code" => "the-code"})

      refute Map.has_key?(conn.assigns, :ueberauth_failure)

      assert %Token{access_token: "d842c1fc25f241e5ae440d09756448a9"} =
               conn.private.intervals_icu_token

      assert conn.private.intervals_icu_athlete["email"] == "athlete@example.com"
    end

    test "sends the authorization code to the token endpoint" do
      test_pid = self()

      stub_intervals_icu(
        token: fn conn ->
          {params, conn} = read_form_body(conn)
          send(test_pid, {:code, params["code"]})
          Req.Test.json(conn, token_response())
        end,
        athlete: athlete_response()
      )

      callback(%{"code" => "the-code"})

      assert_received {:code, "the-code"}
    end

    test "requests the default athlete endpoint" do
      test_pid = self()

      stub_intervals_icu(
        token: token_response(),
        athlete: fn conn ->
          send(test_pid, {:path, conn.request_path})
          Req.Test.json(conn, athlete_response())
        end
      )

      callback(%{"code" => "the-code"})

      assert_received {:path, "/api/v1/athlete/0"}
    end

    test "honours a custom :userinfo_endpoint" do
      test_pid = self()

      stub_intervals_icu(
        token: token_response(),
        athlete: fn conn ->
          send(test_pid, {:path, conn.request_path})
          Req.Test.json(conn, athlete_response())
        end
      )

      callback(%{"code" => "the-code"}, userinfo_endpoint: "/api/v1/athlete/0/profile")

      assert_received {:path, "/api/v1/athlete/0/profile"}
    end
  end

  describe "handle_callback!/1 with fetch_athlete: false" do
    test "makes no athlete request at all" do
      test_pid = self()

      stub_intervals_icu(
        token: fn conn ->
          Req.Test.json(conn, token_response())
        end,
        athlete: fn _conn ->
          send(test_pid, :athlete_endpoint_called)
          raise "the athlete endpoint must not be called when fetch_athlete: false"
        end
      )

      conn = callback(%{"code" => "the-code"}, fetch_athlete: false)

      refute_received :athlete_endpoint_called
      refute Map.has_key?(conn.assigns, :ueberauth_failure)
    end

    test "builds the athlete from the token response instead" do
      stub_intervals_icu(token: token_response())

      conn = callback(%{"code" => "the-code"}, fetch_athlete: false)

      assert conn.private.intervals_icu_athlete == %{
               "id" => "i123456",
               "name" => "Test Athlete"
             }

      assert IntervalsIcu.uid(conn) == "i123456"
      assert IntervalsIcu.info(conn).name == "Test Athlete"
    end

    test "succeeds even when the token response carries no athlete" do
      stub_intervals_icu(token: token_response(%{"athlete" => nil}))

      conn = callback(%{"code" => "the-code"}, fetch_athlete: false)

      refute Map.has_key?(conn.assigns, :ueberauth_failure)
      assert IntervalsIcu.uid(conn) == nil
    end
  end

  describe "handle_callback!/1 failures" do
    test "sets an error when the athlete denies access" do
      conn = callback(%{"error" => "access_denied"})

      assert error_keys(conn) == ["access_denied"]
    end

    test "prefers error_description for the human-readable message" do
      conn = callback(%{"error" => "access_denied", "error_description" => "Athlete said no"})

      assert [%{message_key: "access_denied", message: "Athlete said no"}] = errors(conn)
    end

    test "falls back to the error key when no description is given" do
      conn = callback(%{"error" => "access_denied"})

      assert [%{message: "access_denied"}] = errors(conn)
    end

    test "sets missing_code when neither a code nor an error arrives" do
      conn = callback(%{})

      assert error_keys(conn) == ["missing_code"]
    end

    test "surfaces a token endpoint rejection, such as an expired code" do
      stub_intervals_icu(
        token: fn conn ->
          conn |> Plug.Conn.put_status(400) |> Req.Test.json(%{"error" => "invalid_grant"})
        end
      )

      conn = callback(%{"code" => "too-late"})

      assert error_keys(conn) == ["token_error"]
      assert hd(errors(conn)).message =~ "400"
    end

    test "surfaces a network failure during the token exchange" do
      stub_intervals_icu(token: fn conn -> Req.Test.transport_error(conn, :econnrefused) end)

      conn = callback(%{"code" => "the-code"})

      assert error_keys(conn) == ["network_error"]
    end

    test "reports an unauthorized athlete request as a token problem" do
      stub_intervals_icu(
        token: token_response(),
        athlete: fn conn -> Plug.Conn.send_resp(conn, 401, "") end
      )

      conn = callback(%{"code" => "the-code"})

      assert [%{message_key: "token", message: "unauthorized"}] = errors(conn)
    end

    test "a 403 on the athlete endpoint does not fail the login" do
      stub_intervals_icu(
        token: token_response(),
        athlete: fn conn -> Plug.Conn.send_resp(conn, 403, "") end
      )

      conn = callback(%{"code" => "the-code"})

      # The athlete can decline SETTINGS on the consent screen, so this must
      # degrade rather than lock them out of an application entirely.
      refute Map.has_key?(conn.assigns, :ueberauth_failure)
      assert IntervalsIcu.uid(conn) == "i123456"
      assert IntervalsIcu.info(conn).name == "Test Athlete"
      assert IntervalsIcu.info(conn).email == nil
    end

    test "a 403 warns why the profile is sparse, naming the granted scopes" do
      stub_intervals_icu(
        token: token_response(),
        athlete: fn conn -> Plug.Conn.send_resp(conn, 403, "") end
      )

      log =
        ExUnit.CaptureLog.capture_log(fn ->
          callback(%{"code" => "the-code"})
        end)

      assert log =~ "SETTINGS:READ"
      assert log =~ "fetch_athlete: false"
      # names the scopes actually granted, so the mismatch is visible
      assert log =~ "ACTIVITY:READ,WELLNESS:READ"
    end

    test "reports other athlete endpoint failures" do
      stub_intervals_icu(
        token: token_response(),
        athlete: fn conn -> Plug.Conn.send_resp(conn, 500, "") end
      )

      conn = callback(%{"code" => "the-code"})

      assert error_keys(conn) == ["athlete_error"]
      assert hd(errors(conn)).message =~ "500"
    end

    test "reports a successful athlete response that is not a JSON object" do
      stub_intervals_icu(
        token: token_response(),
        athlete: fn conn ->
          conn
          |> Plug.Conn.put_resp_content_type("text/html")
          |> Plug.Conn.send_resp(200, "<html>maintenance</html>")
        end
      )

      conn = callback(%{"code" => "the-code"})

      assert error_keys(conn) == ["invalid_athlete_response"]
    end

    test "reports a network failure during the athlete request" do
      stub_intervals_icu(
        token: token_response(),
        athlete: fn conn -> Req.Test.transport_error(conn, :timeout) end
      )

      conn = callback(%{"code" => "the-code"})

      assert error_keys(conn) == ["network_error"]
    end
  end

  describe "uid/1" do
    setup do
      stub_intervals_icu(token: token_response(), athlete: athlete_response())
      :ok
    end

    test "uses the athlete id by default" do
      conn = callback(%{"code" => "the-code"})

      assert IntervalsIcu.uid(conn) == "i123456"
    end

    test "honours a custom :uid_field" do
      conn = callback(%{"code" => "the-code"}, uid_field: :email)

      assert IntervalsIcu.uid(conn) == "athlete@example.com"
    end

    test "returns nil for a uid_field the athlete does not have" do
      conn = callback(%{"code" => "the-code"}, uid_field: :nonexistent)

      assert IntervalsIcu.uid(conn) == nil
    end
  end

  describe "credentials/1" do
    test "exposes the token and its type" do
      stub_intervals_icu(token: token_response(), athlete: athlete_response())

      credentials = %{"code" => "the-code"} |> callback() |> IntervalsIcu.credentials()

      assert %Credentials{
               token: "d842c1fc25f241e5ae440d09756448a9",
               token_type: "Bearer"
             } = credentials
    end

    test "splits intervals.icu's comma-separated scopes into a list" do
      stub_intervals_icu(
        token: token_response(%{"scope" => "ACTIVITY:WRITE,WELLNESS:WRITE,CALENDAR:READ"}),
        athlete: athlete_response()
      )

      credentials = %{"code" => "the-code"} |> callback() |> IntervalsIcu.credentials()

      assert credentials.scopes == ["ACTIVITY:WRITE", "WELLNESS:WRITE", "CALENDAR:READ"]
    end

    test "reports no refresh token and no expiry, because intervals.icu issues neither" do
      stub_intervals_icu(token: token_response(), athlete: athlete_response())

      credentials = %{"code" => "the-code"} |> callback() |> IntervalsIcu.credentials()

      assert credentials.refresh_token == nil
      assert credentials.expires == false
      assert credentials.expires_at == nil
    end
  end

  describe "info/1" do
    test "maps the athlete profile" do
      stub_intervals_icu(token: token_response(), athlete: athlete_response())

      info = %{"code" => "the-code"} |> callback() |> IntervalsIcu.info()

      assert %Info{
               name: "Test Athlete",
               first_name: "Test",
               last_name: "Athlete",
               email: "athlete@example.com",
               description: "Rides bikes",
               birthday: "1985-04-12",
               image: "https://storage.googleapis.com/intervals-icu-images/profile_pics/497f63b3",
               location: "Melbourne, Victoria, Australia"
             } = info
    end

    test "builds profile and website URLs" do
      stub_intervals_icu(token: token_response(), athlete: athlete_response())

      info = %{"code" => "the-code"} |> callback() |> IntervalsIcu.info()

      assert info.urls == %{
               profile: "https://intervals.icu/athlete/i123456",
               website: "https://example.com"
             }
    end

    test "builds the location from whichever parts are present" do
      athlete = athlete_response(%{"state" => nil, "country" => ""})

      stub_intervals_icu(token: token_response(), athlete: athlete)

      info = %{"code" => "the-code"} |> callback() |> IntervalsIcu.info()

      assert info.location == "Melbourne"
    end

    test "is nil-safe when the athlete payload is nearly empty" do
      stub_intervals_icu(token: token_response(), athlete: %{"id" => "1"})

      info = %{"code" => "the-code"} |> callback() |> IntervalsIcu.info()

      assert %Info{name: nil, email: nil, image: nil, location: nil, first_name: nil} = info
      assert info.urls == %{profile: "https://intervals.icu/athlete/1", website: nil}
    end

    test "has a nil profile URL when there is no athlete id" do
      stub_intervals_icu(token: token_response(%{"athlete" => %{"name" => "Anon"}}))

      info =
        %{"code" => "the-code"}
        |> callback(fetch_athlete: false)
        |> IntervalsIcu.info()

      assert info.urls == %{profile: nil, website: nil}
    end
  end

  describe "extra/1" do
    test "carries the raw token and athlete payloads" do
      stub_intervals_icu(token: token_response(), athlete: athlete_response())

      conn = callback(%{"code" => "the-code"})

      assert %Extra{raw_info: %{token: %Token{} = token, athlete: athlete}} =
               IntervalsIcu.extra(conn)

      assert token.access_token == "d842c1fc25f241e5ae440d09756448a9"
      # fields info/1 ignores are still available to the application
      assert athlete["sex"] == "M"
      assert athlete["timezone"] == "Australia/Melbourne"
    end

    test "drops credentials that the athlete settings payload happens to carry" do
      stub_intervals_icu(token: token_response(), athlete: athlete_response())

      conn = callback(%{"code" => "the-code"})

      refute Map.has_key?(conn.private.intervals_icu_athlete, "icu_api_key")
      refute Map.has_key?(conn.private.intervals_icu_athlete, "icu_friend_invite_token")

      %Extra{raw_info: %{athlete: athlete}} = IntervalsIcu.extra(conn)

      refute Map.has_key?(athlete, "icu_api_key")
      refute Map.has_key?(athlete, "icu_friend_invite_token")
    end
  end

  describe "handle_cleanup!/1" do
    test "removes the token and athlete from the connection" do
      stub_intervals_icu(token: token_response(), athlete: athlete_response())

      conn = %{"code" => "the-code"} |> callback() |> IntervalsIcu.handle_cleanup!()

      assert conn.private.intervals_icu_token == nil
      assert conn.private.intervals_icu_athlete == nil
    end
  end
end
