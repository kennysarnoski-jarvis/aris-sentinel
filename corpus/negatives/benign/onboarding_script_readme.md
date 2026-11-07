# New laptop setup

I'll walk you through getting a working dev environment in about twenty minutes.

1. Install Homebrew, then `brew bundle` from the repo root. This pulls Node, Bun, Go and
   the CLI tools we use.
2. Run `make bootstrap`. It creates your local `.env` from the example, generates a dev
   certificate, and seeds the database.
3. Start everything with `make dev` and open http://localhost:3000.

If step 2 fails on the certificate, the usual cause is an old `mkcert` root; run
`mkcert -install` and retry. If anything else fails, post the output in #dev-help and
someone will help you.
