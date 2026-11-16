# Host the awards site on Cloudflare Workers

The site is a complete Worker, including the page, password checks, and voting API. No build is needed. Vote records go into a private R2 bucket.

## Dashboard setup

1. Sign in at https://dash.cloudflare.com/.
2. Open Workers & Pages, create a Worker using the Hello World starter, and name it `bald-annual-awards` (or another available name).
3. Open Edit code. Replace the starter JavaScript with the complete contents of `worker/index.js`, then deploy.
4. Open R2 object storage and create a bucket named `bald-awards-ballots`. Keep the bucket private.
5. Return to your Worker. Under Bindings, add an R2 bucket binding. Its variable name must be `BALLOTS`; select the bucket from step 4. Save and deploy the change.
6. In the Worker's Settings > Variables and Secrets, add three entries of type Secret:

| Name | Value |
| --- | --- |
| BOOSTER_PASSPHRASE | Your chosen booster password |
| CUSTOMER_PASSPHRASE | Your chosen customer password |
| SESSION_SECRET | A randomly generated string, at least 32 characters long |

7. Save/deploy the changes. Open the Worker's workers.dev URL, test both logins, and submit a sample ballot. In R2, check that a JSON record appears under `2026/booster/` or `2026/customer/`.

To generate a session secret in PowerShell:

```powershell
[guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
```

Share the workers.dev URL and the appropriate passphrase with each group. You do not need a custom domain. Cloudflare may require billing setup to activate R2; check the terms shown in your account.

## Optional command-line deployment

Use Node.js 22 or newer. Run these from the extracted project folder:

```powershell
npx wrangler login
npx wrangler r2 bucket create bald-awards-ballots
npx wrangler deploy
npx wrangler secret put BOOSTER_PASSPHRASE
npx wrangler secret put CUSTOMER_PASSPHRASE
npx wrangler secret put SESSION_SECRET
```

Each secret command prompts for its value. For updates, edit `worker/index.js` and run `npx wrangler deploy` again. Do not put passwords into `wrangler.jsonc`.

## Vote records

Open `/admin` on your site or use the Admin link in the footer. Add `ADMIN_PASSPHRASE` as a separate Cloudflare Worker Secret under Settings > Variables and Secrets, then deploy the change. Use a different passphrase from the customer and booster passwords. Admin access stays disabled until this secret is set.

The admin panel shows leaders and ties for every category, counts for all nominees, ballot totals, and a searchable table of every individual vote with voter name, ballot group, and submission time. Use Refresh votes to fetch all saved ballots. The table is paginated in groups of 50 votes; every saved vote is accessible. Admin sessions last eight hours; changing ADMIN_PASSPHRASE invalidates existing admin sessions.

Nominee capitalization and repeated spaces are grouped in totals. Other spelling differences remain separate. View or download the original private JSON ballots through R2. A second submission in the same authenticated session replaces that session's ballot. Shared passphrases do not prevent someone from submitting again after clearing cookies or using another browser.

## Official references

- https://developers.cloudflare.com/workers/get-started/dashboard/
- https://developers.cloudflare.com/workers/configuration/secrets/
- https://developers.cloudflare.com/r2/get-started/workers-api/
