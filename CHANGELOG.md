# Changelog

## [0.1.2](https://github.com/hjemmel/ueberauth_intervals_icu/compare/v0.1.1...v0.1.2) (2026-08-13)


### Bug Fixes

* degrade instead of failing when the athlete declines SETTINGS ([54e5e06](https://github.com/hjemmel/ueberauth_intervals_icu/commit/54e5e0695715384c33f87111ef47ce988c51a9f7))
* degrade instead of failing when the athlete declines SETTINGS ([ed61194](https://github.com/hjemmel/ueberauth_intervals_icu/commit/ed61194480099d7fb1d635a65deec6b5d26671ca))

## [0.1.1](https://github.com/hjemmel/ueberauth_intervals_icu/compare/v0.1.0...v0.1.1) (2026-08-12)


### Bug Fixes

* add SETTINGS:READ to the default scope ([ac8054c](https://github.com/hjemmel/ueberauth_intervals_icu/commit/ac8054c97c74105fb9258f6715a017f88e9dabb2))
* fetch query params before reading them in both phases ([81304f5](https://github.com/hjemmel/ueberauth_intervals_icu/commit/81304f52e4bbf67068a67841df470203ac8e93d6))
* fetch query params before reading them in both phases ([9bbe76a](https://github.com/hjemmel/ueberauth_intervals_icu/commit/9bbe76aa9d7e5f59edf981aeda7d9b099f4075bd))
* map the real athlete fields and drop stray credentials ([5bdeb41](https://github.com/hjemmel/ueberauth_intervals_icu/commit/5bdeb416c022699bb402633b482f1e3c0718270f))

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
