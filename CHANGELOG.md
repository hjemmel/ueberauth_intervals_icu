# Changelog

## 0.1.0 (2026-08-12)

Initial release.

### Features

* Ueberauth strategy for authenticating athletes with intervals.icu, covering
  the request and callback phases.
* `Ueberauth.Strategy.IntervalsIcu.OAuth` for authorize-URL construction, the
  token exchange, and authenticated API requests, backed by
  [Req](https://github.com/wojtekmach/req).
* `Ueberauth.Strategy.IntervalsIcu.Token`, modelling the intervals.icu token
  response and its comma-separated scopes.
* `:fetch_athlete` option (default `true`) controlling whether the athlete
  endpoint is called after the token exchange. Setting it to `false` falls back
  to the athlete data already present in the token response, for applications
  whose scopes do not cover `/api/v1/athlete/0`.
* `:req_options` passthrough for custom pools, timeouts and retry policies.

### Notes

* intervals.icu issues no refresh tokens and no expiry, so `credentials` always
  reports `refresh_token: nil`, `expires: false` and `expires_at: nil`.
* HTTP retries are disabled by default. OAuth callbacks are interactive, and the
  authorization code is only valid for two minutes.
