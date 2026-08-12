defmodule Ueberauth.Strategy.IntervalsIcu.Token do
  @moduledoc """
  The access token returned by the intervals.icu token endpoint.

  intervals.icu returns a deliberately small token payload:

      {
        "token_type": "Bearer",
        "access_token": "d842c1fc25f241e5ae440d09756448a9",
        "scope": "ACTIVITY:WRITE,WELLNESS:WRITE",
        "athlete": { "id": "2049151", "name": "David (intervals.icu)" }
      }

  Two things are worth calling out, because they differ from most OAuth 2.0
  providers:

    * There is **no** `refresh_token` and **no** `expires_in`. Tokens do not
      expire on a timer. See `Ueberauth.Strategy.IntervalsIcu` for what that
      means for your application.

    * The athlete's id and name are included in the token response itself, so a
      separate user-info request is optional rather than required.

  Any field intervals.icu adds in the future is preserved in `:other_params`
  rather than being discarded.
  """

  @known_fields ~w(access_token token_type scope athlete)

  @type athlete :: %{optional(String.t()) => term()}

  @type t :: %__MODULE__{
          access_token: String.t(),
          token_type: String.t(),
          scope: String.t() | nil,
          athlete: athlete(),
          other_params: %{optional(String.t()) => term()}
        }

  defstruct [:access_token, :token_type, :scope, athlete: %{}, other_params: %{}]

  @doc """
  Builds a token from a decoded token-endpoint response body.

  Returns `:error` when the body is not a map or carries no usable
  `access_token`.

  ## Examples

      iex> {:ok, token} =
      ...>   Ueberauth.Strategy.IntervalsIcu.Token.from_response(%{
      ...>     "token_type" => "Bearer",
      ...>     "access_token" => "abc123",
      ...>     "scope" => "ACTIVITY:READ,WELLNESS:READ",
      ...>     "athlete" => %{"id" => "2049151", "name" => "David"}
      ...>   })
      iex> token.access_token
      "abc123"
      iex> token.athlete["id"]
      "2049151"

      iex> Ueberauth.Strategy.IntervalsIcu.Token.from_response(%{"error" => "invalid_grant"})
      :error
  """
  @spec from_response(term()) :: {:ok, t()} | :error
  def from_response(%{"access_token" => access_token} = body)
      when is_binary(access_token) and access_token != "" do
    {:ok,
     %__MODULE__{
       access_token: access_token,
       token_type: Map.get(body, "token_type") || "Bearer",
       scope: Map.get(body, "scope"),
       athlete: normalize_athlete(Map.get(body, "athlete")),
       other_params: Map.drop(body, @known_fields)
     }}
  end

  def from_response(_body), do: :error

  @doc """
  The token's granted scopes, as a list.

  intervals.icu joins scopes with **commas**, not the spaces used by most OAuth
  2.0 providers, so this cannot be a plain `String.split/2` on whitespace.

  ## Examples

      iex> alias Ueberauth.Strategy.IntervalsIcu.Token
      iex> Token.scopes(%Token{scope: "ACTIVITY:READ,WELLNESS:WRITE"})
      ["ACTIVITY:READ", "WELLNESS:WRITE"]

      iex> alias Ueberauth.Strategy.IntervalsIcu.Token
      iex> Token.scopes(%Token{scope: nil})
      []
  """
  @spec scopes(t()) :: [String.t()]
  def scopes(%__MODULE__{scope: scope}) when is_binary(scope) do
    scope
    |> String.split(",")
    |> Enum.map(&String.trim/1)
    |> Enum.reject(&(&1 == ""))
  end

  def scopes(%__MODULE__{}), do: []

  defp normalize_athlete(athlete) when is_map(athlete), do: athlete
  defp normalize_athlete(_), do: %{}
end
