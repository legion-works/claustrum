# OpenCode config-fetch spike

This spike proves that OpenCode 1.18.25 gives a config-hook provider option
precedence over the shipped provider loader, including the `fetch` function used
by the AI SDK. It uses only loopback traffic and tombstone credentials under
`/tmp/opencode/oc-spike`; it never contacts a vendor endpoint or reads the user's
OpenCode auth files.

Run the real arms from this checkout:

```sh
unshare -rn sh -c 'ip link set lo up; bash scripts/spikes/opencode-config-fetch.sh'
```

The harness starts a loopback stub for both the OpenAI-compatible chat-completion
shape and the xAI Responses shape, then runs `deepseek/spike` and `xai/spike`.
The stub records all request headers so the output can prove the tombstone
Authorization value reached the wire. The xAI fixture has an expired OAuth entry;
success through the local stub in the network namespace is the offline proof that
the shipped refresh path did not own the request.

The offline namespace matters independently for xAI's `shipped_refresh=0` line. If
xai.ts had run its own fetch, it would have attempted to refresh the sentinel refresh
token; a failed refresh throws before the local stub receives a request. The sentinel
arriving at the stub is therefore evidence that the shipped fetch did not run, while
the namespace separately guarantees no vendor endpoint was reachable. In some
environments the offline form can hang after the models.dev fetch failure; run it with
`timeout` when that happens.

The mutation arm disables only the custom-fetch installation:

```sh
unshare -rn sh -c 'ip link set lo up; SPIKE_DISABLE_CUSTOM_FETCH=1 bash scripts/spikes/opencode-config-fetch.sh'
```

It must fail with a final line containing `SPIKE FAIL deepseek custom_fetch=0`.
That failure is load-bearing: without it, a fixture could pass while never
proving fetch ownership.
