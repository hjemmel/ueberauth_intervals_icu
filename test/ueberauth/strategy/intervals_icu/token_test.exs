defmodule Ueberauth.Strategy.IntervalsIcu.TokenTest do
  use ExUnit.Case, async: true

  import Ueberauth.IntervalsIcu.TestHelpers

  alias Ueberauth.Strategy.IntervalsIcu.Token

  doctest Token

  describe "from_response/1" do
    test "parses the documented intervals.icu token payload" do
      assert {:ok, token} = Token.from_response(token_response())

      assert %Token{
               access_token: "d842c1fc25f241e5ae440d09756448a9",
               token_type: "Bearer",
               scope: "ACTIVITY:READ,WELLNESS:READ",
               athlete: %{"id" => "2049151", "name" => "David (intervals.icu)"},
               other_params: %{}
             } = token
    end

    test "defaults token_type to Bearer when absent" do
      {:ok, token} = Token.from_response(%{"access_token" => "abc"})

      assert token.token_type == "Bearer"
    end

    test "defaults the athlete to an empty map when absent or not a map" do
      {:ok, without} = Token.from_response(%{"access_token" => "abc"})
      {:ok, wrong_type} = Token.from_response(%{"access_token" => "abc", "athlete" => "nope"})

      assert without.athlete == %{}
      assert wrong_type.athlete == %{}
    end

    test "keeps unrecognised fields in other_params rather than discarding them" do
      {:ok, token} =
        Token.from_response(token_response(%{"future_field" => "value", "issued_at" => 123}))

      assert token.other_params == %{"future_field" => "value", "issued_at" => 123}
    end

    test "rejects a body with no access token" do
      assert Token.from_response(%{"error" => "invalid_grant"}) == :error
    end

    test "rejects a blank or non-binary access token" do
      assert Token.from_response(%{"access_token" => ""}) == :error
      assert Token.from_response(%{"access_token" => nil}) == :error
      assert Token.from_response(%{"access_token" => 42}) == :error
    end

    test "rejects a non-map body" do
      assert Token.from_response("<html>Gateway Timeout</html>") == :error
      assert Token.from_response(nil) == :error
    end
  end

  describe "scopes/1" do
    test "splits on commas, not whitespace" do
      token = %Token{scope: "ACTIVITY:READ,WELLNESS:WRITE,CALENDAR:READ"}

      assert Token.scopes(token) == ["ACTIVITY:READ", "WELLNESS:WRITE", "CALENDAR:READ"]
    end

    test "does not split a single scope containing no comma" do
      assert Token.scopes(%Token{scope: "ACTIVITY:READ"}) == ["ACTIVITY:READ"]
    end

    test "trims incidental whitespace around scopes" do
      assert Token.scopes(%Token{scope: "ACTIVITY:READ, WELLNESS:READ"}) ==
               ["ACTIVITY:READ", "WELLNESS:READ"]
    end

    test "returns an empty list for nil or empty scope" do
      assert Token.scopes(%Token{scope: nil}) == []
      assert Token.scopes(%Token{scope: ""}) == []
      assert Token.scopes(%Token{scope: ",,"}) == []
    end
  end
end
