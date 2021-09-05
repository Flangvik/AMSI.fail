# Cloudflare Worker

## Deploying

1. Create a Cloudflare account
2. Install wrangler to deploy from your terminal
```
npm install -g @cloudflare/wrangler
wrangler login
```
3. Create a subdomain for your workers.
```
wrangler subdomain <name>
```
4. Run `wrangler whoami` and copy the account id that is returned into
`wrangler.toml`
5. Deploy the worker: `wrangler publish`
6. Success! Check your worker at `https://amsi-fail.<your-subdomain>.workers.dev/api/Generate`