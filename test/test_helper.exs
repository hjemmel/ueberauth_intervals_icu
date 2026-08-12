alias Ueberauth.Strategy.IntervalsIcu.OAuth

# Every test runs against Req.Test's in-process plug adapter, so no test in this
# suite opens a socket. Stubs are registered per-process, which keeps the suite
# safe to run with `async: true`.
Application.put_env(:ueberauth, OAuth,
  client_id: "test_client_id",
  client_secret: "test_client_secret",
  req_options: [plug: {Req.Test, OAuth}]
)

ExUnit.start()
