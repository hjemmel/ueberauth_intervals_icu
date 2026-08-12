# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

Initial release.

### Added

- `Ueberauth.Strategy.IntervalsIcu`, implementing the request and callback
  phases against the intervals.icu OAuth endpoints.
- `Ueberauth.Strategy.IntervalsIcu.OAuth` for authorize-URL construction, the
  token exchange, and authenticated API requests, backed by
  [Req](https://github.com/wojtekmach/req).
- `Ueberauth.Strategy.IntervalsIcu.Token`, modelling the intervals.icu token
  response and its comma-separated scopes.
- `:fetch_athlete` option (default `true`) to control whether the athlete
  endpoint is called after the token exchange, with `false` falling back to the
  athlete data already present in the token response.
- `:req_options` passthrough for custom pools, timeouts and retry policies.

### Notes

- intervals.icu issues no refresh tokens and no expiry, so `credentials` always
  reports `refresh_token: nil`, `expires: false` and `expires_at: nil`.
- HTTP retries are disabled by default; OAuth callbacks are interactive and the
  authorization code is only valid for two minutes.

[Unreleased]: https://github.com/hjemmel/ueberauth_intervals_icu/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hjemmel/ueberauth_intervals_icu/releases/tag/v0.1.0
