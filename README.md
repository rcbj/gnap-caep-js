# gnap-caep-client

A **GNAP** ([RFC 9635](https://www.rfc-editor.org/rfc/rfc9635)) client for browser single-page apps, written in JavaScript with TypeScript declarations, and a demo app built on it. The client instance runs in the page: it is identified by a key generated in the browser, signs every request with HTTP message signatures, signs people in through a grant they approve at the authorization server, and receives CAEP security events through the Shared Signals Framework.

It is the GNAP counterpart of [`oidc-caep-client`](https://github.com/rcbj/oidc-caep-client), and it is built and tested against [iya-sts](https://rcbj.github.io/iya-sts/gnap.html)'s GNAP authorization server.

**Documentation:** <https://rcbj.github.io/gnap-caep-js/>

| Path | |
|---|---|
| [`packages/gnap-caep-client`](packages/gnap-caep-client) | The library, published to npm as [`gnap-caep-client`](https://www.npmjs.com/package/gnap-caep-client). |
| [`demo`](demo) | A demo single-page app, run in one container. |
| [`scripts/configure-iya-sts.mjs`](scripts/configure-iya-sts.mjs) | Registers the demo as a GNAP client on a running iya-sts. |

## Install

```sh
npm install gnap-caep-client
```

See the [package README](packages/gnap-caep-client/README.md) for the reference and the [SPA guide](packages/gnap-caep-client/docs/spa-guide.md) for a walkthrough.

## Run the demo

```sh
docker compose up --build
```

Register the demo application on iya-sts once (no client key: each browser's key is an instance of the application, named by `class_id`):

```sh
ADMIN_API_CLIENT_SECRET=… npm run configure-iya-sts
```

Open <http://localhost:3000> and sign in. See [Running the demo](docs/demo.md).

## Develop

```sh
npm install
npm test
npm run test:types
```

### Live test against iya-sts

```sh
python3 scripts/live_iya_sts.py
```

It starts a fresh iya-sts from its `main` branch (memory mode, no persistence or clustering), registers the demo's GNAP application, and signs in through the demo in headless Chromium (Playwright's official container image): the SPA starts a grant, iya-sts shows its sign-in screen and its GNAP approval page, every right is approved, and the browser comes back to the SPA's finish URI. It then emits a CAEP `credential-change` and a `session-revoked`, and requires the page to show the first while still signed in and to be signed out after the second. It needs only Docker and the host's Python 3; Node and the browser run in containers. `IYA_STS_IMAGE` starts the fresh container from an image you already have, `IYA_STS_URL` uses a running iya-sts, and `LIVE_STS_PORT` / `LIVE_DEMO_PORT` (default 18505 and 18605) choose the ports. The `Nightly` workflow runs the unit suite and this test every day at 06:19 UTC.

Branch from `develop`. See [Development and releases](docs/development.md).

## License

MIT © 2026 Iya CyberSecurity Solutions, LLC. See [LICENSE](LICENSE).
