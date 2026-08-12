defmodule Ueberauth.Strategy.IntervalsIcu.OAuth do
  @moduledoc """
  OAuth client for intervals.icu.

  This module owns every HTTP conversation with intervals.icu: building the
  authorize URL, exchanging an authorization code for a token, and making
  authenticated API calls on the token's behalf.

  ## Configuration

      config :ueberauth, Ueberauth.Strategy.IntervalsIcu.OAuth,
        client_id: System.get_env("INTERVALS_ICU_CLIENT_ID"),
        client_secret: System.get_env("INTERVALS_ICU_CLIENT_SECRET")

  ## Endpoints

  Note that the authorize and token endpoints live under **different path
  prefixes**, which is why both are configured as absolute URLs:

      https://intervals.icu/oauth/authorize        # authorize
      https://intervals.icu/api/oauth/token        # token

  Both are overridable via `:authorize_url` and `:token_url` should
  intervals.icu ever move them.

  ## Passing options to Req

  Anything under `:req_options` is merged into every request — and wins over
  this module's own defaults — which is how you supply a custom Finch pool, a
  retry policy, timeouts, or a test plug:

      config :ueberauth, Ueberauth.Strategy.IntervalsIcu.OAuth,
        client_id: "...",
        client_secret: "...",
        req_options: [receive_timeout: 10_000]

  ### Retries are off by default

  Req retries transient failures with backoff out of the box. This module turns
  that off, because an OAuth callback is an interactive request: the athlete is
  waiting on a redirect, so several seconds of backoff before an inevitable
  failure is worse than failing fast — and the authorization code is only valid
  for **two minutes**, so a long retry chain can consume the very window it is
  meant to protect.

  If your application would rather retry, say so explicitly:

      req_options: [retry: :safe_transient]

  ## Errors

  `get_access_token/2` reports failures as `{:error, %{key: key, message: message}}`,
  ready to be handed to `Ueberauth.Strategy.Helpers.error/2`.
  """

  alias Ueberauth.Strategy.IntervalsIcu.Token

  @site "https://intervals.icu"
  @authorize_url "https://intervals.icu/oauth/authorize"
  @token_url "https://intervals.icu/api/oauth/token"

  @defaults [
    site: @site,
    authorize_url: @authorize_url,
    token_url: @token_url
  ]

  @type client :: %{
          client_id: String.t(),
          client_secret: String.t(),
          site: String.t(),
          authorize_url: String.t(),
          token_url: String.t(),
          redirect_uri: String.t() | nil,
          req_options: keyword()
        }

  @type error :: %{key: String.t(), message: String.t()}

  @doc """
  Builds the resolved client configuration.

  Application config is merged over the defaults, and `opts` over that, so a
  call site can always override configuration.

  Raises `ArgumentError` when configuration is missing, is not a keyword list,
  or omits `:client_id` / `:client_secret`.
  """
  @spec client(keyword()) :: client()
  def client(opts \\ []) do
    config =
      :ueberauth
      |> Application.get_env(__MODULE__, [])
      |> validate_config!()

    @defaults
    |> Keyword.merge(config)
    |> Keyword.merge(opts)
    |> build_client()
  end

  @doc """
  Builds the URL the athlete is redirected to in order to grant access.

  `params` are merged into the query string. `:scope` and `:state` are the
  interesting ones; `:client_id`, `:redirect_uri` and `:response_type` are
  filled in from the client unless you override them.

  ## Examples

      authorize_url!([scope: "ACTIVITY:READ", state: "csrf"],
        redirect_uri: "https://example.com/auth/intervals_icu/callback")
  """
  @spec authorize_url!(keyword(), keyword()) :: String.t()
  def authorize_url!(params \\ [], opts \\ []) do
    client = client(opts)

    query =
      params
      |> Keyword.put_new(:response_type, "code")
      |> Keyword.put_new(:client_id, client.client_id)
      |> Keyword.put_new(:redirect_uri, client.redirect_uri)
      |> Enum.reject(fn {_key, value} -> is_nil(value) or value == "" end)

    client.authorize_url <> "?" <> URI.encode_query(query)
  end

  @doc """
  Exchanges an authorization code for an access token.

  intervals.icu expects `client_id`, `client_secret` and `code` as
  **form-encoded body parameters** — not HTTP Basic credentials — so that is
  what this sends.

  The code is only valid for **two minutes** after the redirect.

  Returns `{:ok, %Token{}}` or `{:error, %{key: key, message: message}}`.
  """
  @spec get_access_token(keyword(), keyword()) :: {:ok, Token.t()} | {:error, error()}
  def get_access_token(params \\ [], opts \\ []) do
    client = client(opts)
    code = params[:code]

    form = [
      client_id: client.client_id,
      client_secret: client.client_secret,
      code: code
    ]

    request =
      [method: :post, url: client.token_url, form: form]
      |> Keyword.merge(default_req_options())
      |> Keyword.merge(client.req_options)
      |> Req.new()

    case Req.request(request) do
      {:ok, %Req.Response{status: 200, body: body}} ->
        parse_token(body)

      {:ok, %Req.Response{status: status, body: body}} ->
        {:error,
         %{
           key: "token_error",
           message:
             "intervals.icu returned HTTP #{status} from the token endpoint: #{describe(body)}"
         }}

      {:error, exception} ->
        {:error, %{key: "network_error", message: describe_exception(exception)}}
    end
  end

  @doc """
  Performs an authenticated `GET` against the intervals.icu API.

  `url` may be an absolute URL or a path, which is resolved against the
  configured `:site`. The token is sent as an `Authorization: Bearer` header.

  Returns Req's usual `{:ok, %Req.Response{}}` / `{:error, exception}`.

  ## Examples

      get(token, "/api/v1/athlete/0")
  """
  @spec get(Token.t(), String.t(), keyword(), keyword()) ::
          {:ok, Req.Response.t()} | {:error, Exception.t()}
  def get(%Token{} = token, url, headers \\ [], opts \\ []) do
    client = client(opts)

    request =
      [
        method: :get,
        url: absolute_url(client, url),
        auth: {:bearer, token.access_token},
        headers: headers
      ]
      |> Keyword.merge(default_req_options())
      |> Keyword.merge(client.req_options)
      |> Req.new()

    Req.request(request)
  end

  @doc """
  The default intervals.icu endpoints, useful for tests and introspection.
  """
  @spec defaults() :: keyword()
  def defaults, do: @defaults

  # -- internals -------------------------------------------------------------

  # Req retries transient failures by default, with backoff. That is the wrong
  # trade-off during an OAuth callback: the athlete is waiting on a redirect, so
  # several seconds of backoff before an inevitable failure is worse than
  # failing fast — and the authorization code is only valid for two minutes, so
  # a long retry chain can burn the window it is meant to protect.
  #
  # Applications that want retries can turn them back on via :req_options.
  defp default_req_options, do: [retry: false]

  defp validate_config!(config) when is_list(config) do
    if Keyword.keyword?(config) do
      config
    else
      raise ArgumentError, """
      expected :ueberauth, #{inspect(__MODULE__)} configuration to be a keyword list, \
      got: #{inspect(config)}
      """
    end
  end

  defp validate_config!(config) do
    raise ArgumentError, """
    expected :ueberauth, #{inspect(__MODULE__)} configuration to be a keyword list, \
    got: #{inspect(config)}
    """
  end

  defp build_client(config) do
    %{
      client_id: fetch_credential!(config, :client_id),
      client_secret: fetch_credential!(config, :client_secret),
      site: Keyword.fetch!(config, :site),
      authorize_url: Keyword.fetch!(config, :authorize_url),
      token_url: Keyword.fetch!(config, :token_url),
      redirect_uri: Keyword.get(config, :redirect_uri),
      req_options: Keyword.get(config, :req_options, [])
    }
  end

  defp fetch_credential!(config, key) do
    case Keyword.get(config, key) do
      value when is_binary(value) and value != "" ->
        value

      value ->
        raise ArgumentError, """
        missing #{inspect(key)} for #{inspect(__MODULE__)}, got: #{inspect(value)}

        Configure it with:

            config :ueberauth, #{inspect(__MODULE__)},
              client_id: System.get_env("INTERVALS_ICU_CLIENT_ID"),
              client_secret: System.get_env("INTERVALS_ICU_CLIENT_SECRET")
        """
    end
  end

  defp parse_token(body) do
    case Token.from_response(body) do
      {:ok, token} ->
        {:ok, token}

      :error ->
        {:error,
         %{
           key: "invalid_token_response",
           message: "the intervals.icu token endpoint returned no access_token: #{describe(body)}"
         }}
    end
  end

  defp absolute_url(_client, "http://" <> _rest = url), do: url
  defp absolute_url(_client, "https://" <> _rest = url), do: url
  defp absolute_url(client, path), do: client.site <> path

  defp describe(body) when is_binary(body), do: body
  defp describe(body), do: inspect(body)

  defp describe_exception(exception) when is_exception(exception),
    do: Exception.message(exception)

  defp describe_exception(other), do: inspect(other)
end
