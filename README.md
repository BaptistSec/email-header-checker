# Email Header Checker 2.0

Published by William Baptist | Tidy Desk Digital

A free, local header-inspection tool. Open `index.html` in a current browser, paste original message headers and choose **Inspect headers**. The page starts with **Unverified headers**. It never gives a safe-message verdict.

## What changed

- Replaced the duplicated parser with one shared `header-check.js` used by both the page and Node tests.
- Stops at the first blank line. Body text cannot supply authentication results.
- Keeps each Authentication-Results report separate, including its authserv-id. No merging lower-header passes into another report.
- No automatic top-header trust. Selection requires an exact provider ID, a specific report and an explicit independently confirmed trust-boundary statement. These inputs are user assertions, not authentication performed by the tool. Repeated IDs stay unresolved.
- Parses the actual conventional mailbox rather than email-like display-name text. Unsupported or ambiguous mailbox syntax stays unresolved.
- Keeps SPF fail and reported DMARC pass separate, with a limited explanation rather than a phishing verdict.
- Conflicts, unknown results, unsupported versions and malformed syntax remain unverified.
- Output is rendered as text, not interpreted HTML. No external dependencies in the shipped page, no analytics, no network requests, no persistence.

## Trust and limits

A pasted authserv-id can be forged. Ask your mail administrator how to identify the provider's trusted header and how incoming forged copies are removed. If you cannot establish that boundary, leave the result unverified. Even a selected report only says what that header claims.

The tool does not verify signatures, query DNS, calculate alignment or judge links, attachments or message safety. It deliberately supports a subset of syntax, not a full RFC mailbox parser: one ASCII mailbox, no quoted local parts, groups, address lists, international addresses or domain literals. Those cases need manual review. ARC and Received-SPF are not replacements for Authentication-Results here. Maximum input is 200,000 characters. Clear or close the page when finished.

Normative background: RFC 8601, especially sections 1.6, 2.5 and 7: https://www.rfc-editor.org/rfc/rfc8601.html

## Tests

Run `node test.js` from this folder. The release has 56 parser regression tests.

Browser tests are in `browser-test.js`. In a disposable development checkout, run `npm install playwright`, then set `CHROME_PATH` to your installed Chrome executable if it is not `/usr/bin/google-chrome` and run `node browser-test.js`. Installing Playwright beside the test runner lets Node find it. The runner writes Desktop-QA.png and Mobile-QA.png into that checkout. Browser dependencies are test-only and not needed to use the tool.

The included test results describe checks actually run against this build. They are not an independent QA verdict. Scope: local reported-header inspection, not a validator or phishing detector.

## Licence

MIT. See LICENSE.
