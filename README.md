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

Branch from `develop`. See [Development and releases](docs/development.md).

## License

MIT © 2026 Iya CyberSecurity Solutions, LLC. See [LICENSE](LICENSE).
