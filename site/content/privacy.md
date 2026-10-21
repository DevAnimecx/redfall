---
title: Privacy policy
seoTitle: "Privacy Policy | RedFall"
description: "RedFall's site runs no analytics, sets no cookies, has no accounts and self-hosts its font. Here is what the static site and GitHub Pages actually process."
path: privacy/
group: Project
kind: page
order: 2
updated: 2026-10-21
keywords: RedFall privacy policy, no analytics, no cookies
sources: https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement, https://docs.github.com/en/pages
related: about, security
---

**The RedFall site is a static documentation site. It runs no analytics, sets no cookies, has no accounts, no forms and no newsletter, and self-hosts its font.** The only third party involved in a normal page view is GitHub Pages, which serves the files.

This policy describes the site at `https://devanimecx.github.io/redfall/`. It is not a policy for a RedFall scan target, the GitHub repository, or a third-party site you reach from a link.

## What does the site collect?

The site code does not collect personal data.

| Feature | Present? | What it would collect |
| --- | --- | --- |
| Analytics (GA4, Plausible, etc.) | No | Page views, referrers, device data |
| Cookies | No site cookies | Identifiers stored in your browser |
| Accounts or login | No | Names, emails, credentials |
| Contact forms | No | Submitted personal data |
| Newsletter | No | Email addresses |
| Advertising pixels | No | Ad interaction data |
| Third-party scripts | No | Whatever the script collects |

There is no consent banner because there is nothing to consent to. The site does not use `localStorage` or `sessionStorage` for tracking. The only interactive browser features are links, native `<details>` disclosure widgets, and the copy buttons on the landing page, which use the browser clipboard API locally.

## What does GitHub Pages process?

GitHub Pages hosts the site. When you request a page, GitHub's infrastructure processes the request, which may include your IP address, user agent, requested URL and timestamps, under [GitHub's privacy statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement). The site does not receive or store those logs.

GitHub may also set infrastructure cookies or process data for its own services. That processing is GitHub's, not the site's. The site code does not add cookies of its own.

## What about the font and images?

The Inter font is served from the same site (`/redfall/fonts/inter-latin.woff2`). It is not loaded from Google Fonts or another font CDN, so a page view does not create a separate request to a font provider. The logo, icons and social card are local files.

## What happens when you click an external link?

The site links to GitHub, gVisor, OWASP, Semgrep, CodeQL, Sigstore and other primary sources. When you follow a link, the destination site's privacy policy applies. The RedFall site does not receive information about which link you clicked.

## What happens in a GitHub issue?

If you open an issue or a security advisory, GitHub processes the content under its policies. Do not include provider keys, target credentials, customer data or exploit details for systems you do not own. For a sensitive report, use private vulnerability reporting rather than a public issue.

## Does the site use security headers?

GitHub Pages controls the response headers. The site sets a referrer policy and a content security policy in the page where it can, but it cannot set host-level headers such as `X-Frame-Options` or `frame-ancestors` on GitHub Pages. That limitation is documented rather than hidden. It does not change the data collection described above.

## Does the site make automated decisions about you?

No. There is no personalisation, profiling, scoring or automated decision-making.

## What about children?

The site is technical documentation for adults. It does not knowingly collect data from anyone, including children.

## How does this policy change?

If the site adds analytics, accounts or any other data processing, this page will be updated before the change takes effect, with a new date. The current version is dated 2026-10-19.

## How do you ask a privacy question?

Open an issue in the [RedFall repository](https://github.com/DevAnimecx/redfall/issues) with the subject "privacy". Do not include personal data in the issue. For a sensitive report, use the repository's private vulnerability reporting flow.

## What this policy is not

This is a plain-language description of the site's behaviour, not legal advice. It does not create a contract, a data-processing agreement or a representation about GitHub's practices. If you need a legal review for a regulated deployment, consult your own counsel.
