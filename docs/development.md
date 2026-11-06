---
title: Development and releases
---

# Development and releases

## Tests

```sh
npm install
npm test
npm run test:types
```

The tests run with `node:test` against a strict in-memory GNAP authorization server, resource server and SSF transmitter (`packages/gnap-caep-client/test/stub-as.js`), injected through the library's `fetch` option. The stub shares no signing code with the library: it parses `Signature-Input`, rebuilds the RFC 9421 signature base, recomputes the `Content-Digest` and verifies the signature with node's crypto, and computes the interaction hash itself. The suite covers:

- discovery, the configuration checks and TLS;
- the grant request and its signature, the redirect finish and the interaction hash, single use and expiry, the continuation, `too_fast`, denial;
- subject information, `id_token` assertion verification, account binding;
- key-bound tokens at a resource server, bearer downgrade, rotation, revocation, modification;
- the token cache, and several accounts per browser, including routing CAEP events by grant session;
- the SSF receiver with GNAP tokens: polling, catch-up, SET validation, acknowledgement;
- the iya-sts configuration script's plan, offline;
- that the library imports no Node.js built-ins.

`npm run test:types` builds the declarations and type-checks a TypeScript consumer, a `// @ts-check` JavaScript consumer, and the TypeScript example on the site's home page.

Node.js 24.22.1 or later is required (`.nvmrc`).

## Continuous integration

| Workflow | Runs on | Does |
|---|---|---|
| `tests.yml` | every push and pull request | `npm test`, `npm run test:types`, then builds the demo container and smoke-tests the page, its headers and its modules |
| `npm-publish.yml` | pushes to `main` and `develop` that change the package | tests, stamps the version, packs and publishes to npm with provenance |
| `pages.yml` | pushes to `main` that change the docs or the source | builds this site and the API references |

## Branches

- **`develop`** is where work comes together; branch from it and merge back into it.
- **`main`** is what is released.

## Versions and releases

`M.N` is in the `VERSION` file; the patch number is worked out at build time from what is on npm (`scripts/version.mjs`). `main` publishes `M.N.P` under `latest`; `develop` publishes `M.N.P-next.R` under `next`. After bumping `VERSION`, run `npm run version:sync`. Publishing uses the repository secret `NPM_TOKEN`, or npm trusted publishing once configured.

## One-time setup on GitHub and npm

The workflows run as soon as the repository has `main` and `develop`, but two of them need this first.

**GitHub Pages** (`pages.yml`). Pages must exist and build from GitHub Actions. The workflow's own token cannot create it, so someone with admin rights on the repository does it once:

```sh
gh api -X POST repos/rcbj/gnap-caep-js/pages -f build_type=workflow
```

or **Settings → Pages → Source: GitHub Actions**. The site is then published at <https://rcbj.github.io/gnap-caep-js/> on every push to `main` that changes the docs or the library's source.

**npm** (`npm-publish.yml`). The package is published as [`gnap-caep-client`](https://www.npmjs.com/package/gnap-caep-client), with provenance.

1. Create the repository environment **`npm`** (**Settings → Environments**). Add required reviewers to it to hold every publish for approval.
2. For the **first** publish, add the repository secret **`NPM_TOKEN`**: an npm granular access token with publish rights. A trusted publisher can only be configured for a package that already exists.
3. After the first publish, configure **trusted publishing** on npmjs.com (the package's **Settings → Trusted publishing**): repository `rcbj/gnap-caep-js`, workflow `npm-publish.yml`, environment `npm`. Then delete `NPM_TOKEN`.

A push to `main` then publishes a release under `latest`. A push to `develop` publishes nothing, so every release tag is on `main`. A pre-release under `next` comes only from running the workflow by hand on `main`. A pull request builds, tests and packs, and publishes nothing.
