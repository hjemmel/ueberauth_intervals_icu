defmodule Ueberauth.Strategy.IntervalsIcu.OAuthTest do
  use ExUnit.Case, async: true

  import Ueberauth.IntervalsIcu.TestHelpers

  alias Ueberauth.Strategy.IntervalsIcu.OAuth
  alias Ueberauth.Strategy.IntervalsIcu.Token

  describe "client/1" do
    test "uses the documented intervals.icu endpoints by default" do
      client = OAuth.client()

      assert client.site == "https://intervals.icu"
      assert client.authorize_url == "https://intervals.icu/oauth/authorize"
      assert client.token_url == "https://intervals.icu/api/oauth/token"
    end

    test "the authorize and token endpoints sit under different path prefixes" do
      client = OAuth.client()

      assert String.ends_with?(client.authorize_url, "/oauth/authorize")
      assert String.ends_with?(client.token_url, "/api/oauth/token")
      refute client.authorize_url == client.token_url
    end

    test "reads credentials from application config" do
      client = OAuth.client()

      assert client.client_id == "test_client_id"
      assert client.client_secret == "test_client_secret"
    end

    test "call-site options override application config" do
      client = OAuth.client(client_id: "override", token_url: "https://example.test/token")

      assert client.client_id == "override"
      assert client.token_url == "https://example.test/token"
      # untouched keys still come from config
      assert client.client_secret == "test_client_secret"
    end

    test "carries redirect_uri and req_options through" do
      client = OAuth.client(redirect_uri: callback_url())

      assert client.redirect_uri == callback_url()
      assert client.req_options == [plug: {Req.Test, OAuth}]
    end
  end

  describe "authorize_url!/2" do
    test "builds an authorize URL with every documented parameter" do
      url =
        OAuth.authorize_url!(
          [scope: "ACTIVITY:READ,WELLNESS:READ", state: "csrf-token"],
          redirect_uri: callback_url()
        )

      assert %URI{scheme: "https", host: "intervals.icu", path: "/oauth/authorize", query: query} =
               URI.parse(url)

      params = URI.decode_query(query)

      assert params["client_id"] == "test_client_id"
      assert params["redirect_uri"] == callback_url()
      assert params["scope"] == "ACTIVITY:READ,WELLNESS:READ"
      assert params["state"] == "csrf-token"
      assert params["response_type"] == "code"
    end

    test "never leaks the client secret into the authorize URL" do
      url = OAuth.authorize_url!([scope: "ACTIVITY:READ"], redirect_uri: callback_url())

      refute url =~ "test_client_secret"
      refute url =~ "client_secret"
    end

    test "omits parameters that are nil or empty" do
      url = OAuth.authorize_url!([scope: "ACTIVITY:READ", state: nil], [])
      params = url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

      refute Map.has_key?(params, "state")
      refute Map.has_key?(params, "redirect_uri")
    end

    test "explicit params win over the ones derived from the client" do
      url =
        OAuth.authorize_url!(
          [scope: "ACTIVITY:READ", client_id: "explicit", response_type: "token"],
          redirect_uri: callback_url()
        )

      params = url |> URI.parse() |> Map.fetch!(:query) |> URI.decode_query()

      assert params["client_id"] == "explicit"
      assert params["response_type"] == "token"
    end
  end

  describe "get_access_token/2" do
    test "posts client_id, client_secret and code as form body parameters" do
      test_pid = self()

      stub_intervals_icu(
        token: fn conn ->
          {params, conn} = read_form_body(conn)
          send(test_pid, {:token_request, params, conn.method, conn.request_path})
          Req.Test.json(conn, token_response())
        end
      )

      assert {:ok, %Token{}} = OAuth.get_access_token(code: "the-code")

      assert_received {:token_request, params, "POST", "/api/oauth/token"}

      assert params == %{
               "client_id" => "test_client_id",
               "client_secret" => "test_client_secret",
               "code" => "the-code"
             }
    end

    test "sends the credentials in the body, not as an Authorization header" do
      test_pid = self()

      stub_intervals_icu(
        token: fn conn ->
          send(test_pid, {:auth_header, Plug.Conn.get_req_header(conn, "authorization")})
          Req.Test.json(conn, token_response())
        end
      )

      OAuth.get_access_token(code: "the-code")

      assert_received {:auth_header, []}
    end

    test "form-encodes the body" do
      test_pid = self()

      stub_intervals_icu(
        token: fn conn ->
          send(test_pid, {:content_type, Plug.Conn.get_req_header(conn, "content-type")})
          Req.Test.json(conn, token_response())
        end
      )

      OAuth.get_access_token(code: "the-code")

      assert_received {:content_type, [content_type]}
      assert content_type =~ "application/x-www-form-urlencoded"
    end

    test "parses the response into a token, athlete included" do
      stub_intervals_icu(token: token_response())

      assert {:ok, token} = OAuth.get_access_token(code: "the-code")

      assert token.access_token == "d842c1fc25f241e5ae440d09756448a9"
      assert token.token_type == "Bearer"
      assert token.scope == "ACTIVITY:READ,WELLNESS:READ"
      assert token.athlete == %{"id" => "2049151", "name" => "David (intervals.icu)"}
    end

    test "returns an error for a non-200 response" do
      stub_intervals_icu(
        token: fn conn ->
          conn
          |> Plug.Conn.put_status(400)
          |> Req.Test.json(%{"error" => "invalid_grant"})
        end
      )

      assert {:error, %{key: "token_error", message: message}} =
               OAuth.get_access_token(code: "expired")

      assert message =~ "400"
      assert message =~ "invalid_grant"
    end

    test "returns an error when a 200 carries no access token" do
      stub_intervals_icu(token: %{"error" => "something odd"})

      assert {:error, %{key: "invalid_token_response", message: message}} =
               OAuth.get_access_token(code: "the-code")

      assert message =~ "no access_token"
    end

    test "returns an error when the request never completes" do
      stub_intervals_icu(token: fn conn -> Req.Test.transport_error(conn, :econnrefused) end)

      assert {:error, %{key: "network_error", message: message}} =
               OAuth.get_access_token(code: "the-code")

      assert is_binary(message)
    end
  end

  describe "get/4" do
    test "sends the access token as a Bearer header" do
      test_pid = self()

      stub_intervals_icu(
        athlete: fn conn ->
          send(test_pid, {:headers, Plug.Conn.get_req_header(conn, "authorization")})
          Req.Test.json(conn, athlete_response())
        end
      )

      assert {:ok, %Req.Response{status: 200}} = OAuth.get(token(), "/api/v1/athlete/0")

      assert_received {:headers, ["Bearer d842c1fc25f241e5ae440d09756448a9"]}
    end

    test "resolves a relative path against the configured site" do
      test_pid = self()

      stub_intervals_icu(
        athlete: fn conn ->
          send(test_pid, {:target, conn.host, conn.request_path})
          Req.Test.json(conn, athlete_response())
        end
      )

      OAuth.get(token(), "/api/v1/athlete/0")

      assert_received {:target, "intervals.icu", "/api/v1/athlete/0"}
    end

    test "leaves an absolute URL alone" do
      test_pid = self()

      stub_intervals_icu(
        athlete: fn conn ->
          send(test_pid, {:target, conn.host, conn.request_path})
          Req.Test.json(conn, athlete_response())
        end
      )

      OAuth.get(token(), "https://other.example/api/v1/athlete/0")

      assert_received {:target, "other.example", "/api/v1/athlete/0"}
    end

    test "passes extra headers through" do
      test_pid = self()

      stub_intervals_icu(
        athlete: fn conn ->
          send(test_pid, {:custom, Plug.Conn.get_req_header(conn, "x-custom")})
          Req.Test.json(conn, athlete_response())
        end
      )

      OAuth.get(token(), "/api/v1/athlete/0", [{"x-custom", "value"}])

      assert_received {:custom, ["value"]}
    end

    test "surfaces the decoded JSON body" do
      stub_intervals_icu(athlete: athlete_response())

      assert {:ok, %Req.Response{body: body}} = OAuth.get(token(), "/api/v1/athlete/0")

      assert body["email"] == "david@example.com"
    end

    test "returns the error tuple when the request fails" do
      stub_intervals_icu(athlete: fn conn -> Req.Test.transport_error(conn, :timeout) end)

      assert {:error, exception} = OAuth.get(token(), "/api/v1/athlete/0")
      assert is_exception(exception)
    end
  end

  describe "retry behaviour" do
    test "does not retry a failing token exchange" do
      test_pid = self()

      stub_intervals_icu(
        token: fn conn ->
          send(test_pid, :token_attempt)
          conn |> Plug.Conn.put_status(500) |> Req.Test.json(%{})
        end
      )

      assert {:error, %{key: "token_error"}} = OAuth.get_access_token(code: "the-code")

      assert_received :token_attempt
      refute_received :token_attempt
    end

    test "does not retry a failing API request" do
      test_pid = self()

      stub_intervals_icu(
        athlete: fn conn ->
          send(test_pid, :athlete_attempt)
          Plug.Conn.send_resp(conn, 500, "")
        end
      )

      assert {:ok, %Req.Response{status: 500}} = OAuth.get(token(), "/api/v1/athlete/0")

      assert_received :athlete_attempt
      refute_received :athlete_attempt
    end

    test "an application can turn retries back on through req_options" do
      test_pid = self()

      stub_intervals_icu(
        athlete: fn conn ->
          send(test_pid, :athlete_attempt)
          Plug.Conn.send_resp(conn, 500, "")
        end
      )

      OAuth.get(token(), "/api/v1/athlete/0", [],
        req_options: [
          plug: {Req.Test, OAuth},
          retry: :safe_transient,
          max_retries: 1,
          retry_delay: 0
        ]
      )

      assert_received :athlete_attempt
      assert_received :athlete_attempt
    end
  end

  describe "defaults/0" do
    test "exposes the endpoint defaults" do
      assert OAuth.defaults()[:site] == "https://intervals.icu"
      assert OAuth.defaults()[:authorize_url] == "https://intervals.icu/oauth/authorize"
      assert OAuth.defaults()[:token_url] == "https://intervals.icu/api/oauth/token"
    end
  end
end
