# Changelog

## [0.7.1](https://github.com/cipherwire/ja4proxy/compare/v0.7.0...v0.7.1) (2026-10-31)


### Bug Fixes

* **proxy:** per-request profile switching, RFC-compliant CONNECT tunnels, Host rewrite, SSRF-guarded upstream proxies, and CA/CLI hardening ([9f6cb03](https://github.com/cipherwire/ja4proxy/commit/9f6cb030a6e24797a814c140deb4607c51706f03))
* **server:** set protocol._over_ssl to prevent asyncio eof_received warning on TLS teardown ([c18d2e0](https://github.com/cipherwire/ja4proxy/commit/c18d2e0fa97a0e82237fddf54198984999dccbe6))

## [0.7.0](https://github.com/cipherwire/ja4proxy/compare/v0.6.0...v0.7.0) (2026-10-28)


### Features

* **ca:** implement RFC 5280 leaf extensions, reusable leaf key, combined bundle, and inject_trust SDK helper ([6282247](https://github.com/cipherwire/ja4proxy/commit/6282247c81903e9daba59ef4ba449279745e1fed))


### Bug Fixes

* **security:** ephemeral per-host keys, 14-day validity, exact SAN, robust CN uninstall, dynamic doctor verdict with --json, and track docs ([918288c](https://github.com/cipherwire/ja4proxy/commit/918288c7d872573258014553e760c03cd17de9de))

## [0.6.0](https://github.com/cipherwire/ja4proxy/compare/v0.5.0...v0.6.0) (2026-10-28)


### Features

* add ja4proxy doctor diagnostic and one-click ca trust installation ([092504c](https://github.com/cipherwire/ja4proxy/commit/092504cc668d86aed60644a6ecd9ba33ad524b3c))


### Documentation

* add direct pip install and configuration reference to readme ([0072123](https://github.com/cipherwire/ja4proxy/commit/00721239045dd3505e9ae5b0a6e1636e42745111))

## [0.5.0](https://github.com/cipherwire/ja4proxy/compare/v0.4.0...v0.5.0) (2026-10-24)


### Features

* add full docker-compose support and cli environment variables ([669e07b](https://github.com/cipherwire/ja4proxy/commit/669e07ba85f63c2b7854d0726ca3d371e33c37f1))

## [0.4.0](https://github.com/cipherwire/ja4proxy/compare/v0.3.0...v0.4.0) (2026-10-24)


### Features

* add cyberpunk ascii banner and status dashboard to cli ([a829eee](https://github.com/cipherwire/ja4proxy/commit/a829eee820561c99f0179d09b2a51c4df97ef5e1))

## [0.3.0](https://github.com/cipherwire/ja4proxy/compare/v0.2.0...v0.3.0) (2026-10-24)


### Features

* add __main__.py entry point for python -m ja4proxy execution ([ca24232](https://github.com/cipherwire/ja4proxy/commit/ca24232309f9a4a3123c96e01f608922f67945ba))


### Bug Fixes

* wire async cert generation and add client tls handshake timeout ([69fbb91](https://github.com/cipherwire/ja4proxy/commit/69fbb91c9d1e07f6b4fea6d247fb1e08f7bf35f7))

## [0.2.0](https://github.com/cipherwire/ja4proxy/compare/v0.1.1...v0.2.0) (2026-10-24)


### Features

* canonical browser header order, client authentication, and ci timeouts ([204f27d](https://github.com/cipherwire/ja4proxy/commit/204f27dfc46c24fe7da18b3d3353ca6a164f3fa6))

## [0.1.1](https://github.com/cipherwire/ja4proxy/compare/v0.1.0...v0.1.1) (2026-10-24)


### Bug Fixes

* async non-blocking dns, defensive 502 header fallback, ios ua matching, and idle timeout separation ([a53465f](https://github.com/cipherwire/ja4proxy/commit/a53465f7b73c5cde82b4c67c5ccdc515c007a88a))
* guard error body against premature base64 decode and improve 502 assertion ([6dd4dae](https://github.com/cipherwire/ja4proxy/commit/6dd4dae84d65614d1c8eee8a4c96df21ed4283b9))
