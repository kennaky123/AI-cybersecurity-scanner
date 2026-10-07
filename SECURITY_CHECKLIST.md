# Phase 10 Security Checklist

## Input and SSRF

- [x] HTTP(S) URL validation before HTML/sandbox access.
- [x] Reject embedded URL credentials for HTML fetching.
- [x] Block `localhost`, cloud metadata hostnames, loopback, private, link-local, multicast, reserved, unspecified, and non-global addresses.
- [x] Re-resolve DNS immediately before connecting and reject changed/private resolution.
- [x] Disable inherited proxy/environment settings with `trust_env=False`.
- [x] Do not follow redirects in the host-side HTML fetcher.
- [ ] Production DNS pinning inside an isolated network provider remains required for complete rebinding resistance.

## Resource limits and cleanup

- [x] HTML response size limit: 2 MB.
- [x] HTML request timeout: 8 seconds.
- [x] Sandbox timeout and telemetry/event limits are explicit in `SandboxPolicy`.
- [x] Download size limit is represented in sandbox policy.
- [x] Sandbox provider shutdown runs in `finally` after each scan.
- [x] Temporary malware adapter files are deleted in `finally`.
- [x] Downloaded executable execution is blocked by policy and metadata.

## Isolation

- [x] No real browser provider is enabled by default.
- [x] No host browser profile, host credentials, clipboard, shared folder, or filesystem access is granted by the default policy.
- [x] No JavaScript or downloaded executable is executed by the application process.
- [ ] A production container/VM provider must enforce these controls outside the FastAPI process.

## Secrets and APIs

- [x] Threat-intelligence keys are read from environment variables only.
- [x] Provider timeout, auth failure, network failure, and rate-limit states are isolated.
- [x] API error responses do not expose stack traces or secret values.
- [x] CORS remains restricted to configured local frontend origins.

## Verification

- [x] Full regression suite passes.
- [x] Mock provider tests cover redirects, downloads, visual analysis, malware integration, provider errors, timeout behavior, and SSRF checks.
- [x] No real malware or unsafe website was used in tests.
