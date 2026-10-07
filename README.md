# Email Header Checker 2.0

Published by William Baptist | Tidy Desk Digital

[tidydesksoftware@outlook.com](mailto:tidydesksoftware@outlook.com)

A free tool for reading an email's headers, the technical details stored above its message text. It runs on your computer. It does not decide whether an email is safe.

Open `index.html` in a current browser, paste the original message headers and choose **Inspect headers**. The page starts with **Unverified headers**. If you do not know how to find the original headers, use your email provider's instructions or ask the person managing your email.

## What it shows

Some headers contain `Authentication-Results`: reports of checks carried out by a mail system. A domain is a website-style name, such as example.com, or the part after @ in an email address. Common checks include:

- **SPF (Sender Policy Framework):** whether the sending server is permitted to send for the domain used in the delivery details. This is not necessarily the address you see in the From field.
- **DKIM (DomainKeys Identified Mail):** whether a digital signature, a coded mark used to check the signed message, passes the receiving system's check.
- **DMARC (Domain-based Message Authentication, Reporting and Conformance):** whether a passing SPF or DKIM result also meets the required domain match with the address in the From field.

This tool reads what a pasted report says. It does not carry out those checks itself. A reported pass is not proof that the sender is honest or that links and attachments are safe.

Each report has an `authserv-id`, the name identifying the mail system that says it made the report. The tool keeps reports separate. It does not combine passing results from different reports or trust a report just because it appears near the top.

Before selecting a report, you must enter the exact provider ID, select a specific report and confirm that you independently checked where your provider's trusted reports start. Ask your email provider or the person managing your email which report their service added, and how they remove fake copies supplied by outside senders. If you cannot establish that, leave the headers unverified. These choices record what you assert; they are not checks performed by the tool. A pasted ID can be forged. If the provider ID occurs more than once, the choice remains unresolved.

If you cannot establish which report comes from your provider, leave the headers unverified. Even a selected report only says what that header claims.

## Behaviour and limits

- The tool stops at the first blank line. Text from the email's body cannot supply reported check results.
- It reads the actual address in a supported From field, not an email-like name displayed beside it.
- An SPF failure and a reported DMARC pass remain separate. The tool gives a limited explanation, not a verdict about misleading email.
- Conflicting results, unrecognised results, unsupported versions and wrongly formatted text remain unverified.
- It shows pasted text as text, not as instructions for the browser to display a web page.
- The supplied page needs no extra libraries, collects no activity data, makes no network requests and does not save pasted headers. Clear or close the page when finished.
- Maximum input: 200,000 characters.

The tool does not verify digital signatures, look up domain records, calculate the domain matches required by DMARC, or judge links, attachments or message safety.

It supports only part of the email-address formats allowed by the standards: one address using ordinary ASCII characters: supported letters, digits and punctuation, not international characters. It does not support an address with a quoted part before @, groups, address lists, international addresses or address formats using a network address in square brackets instead of a domain name. Those cases need manual review. For technical readers: this is a limited parser, not a full reader for mailbox formats in the published internet technical standards (RFCs).

`ARC` (Authenticated Received Chain, records used to carry checks through forwarding) and `Received-SPF` (another header reporting an SPF result) are not substitutes for `Authentication-Results` in this tool.

The published internet technical standard behind these cautions is RFC 8601, especially sections 1.6, 2.5 and 7:
https://www.rfc-editor.org/rfc/rfc8601.html

## Running the development checks

You do not need these steps to use the page. They are for people testing the code and require Node.js, a program for running JavaScript outside a browser.

From this folder, run:

Swipe code sideways if a line is cut off.

```sh
node test.js
```

The release has 56 automated checks of the code that reads headers. Passing them does not prove an email is safe or count as an independent review.

Browser checks are in `browser-test.js`. In a temporary development copy of this repository, run `npm install playwright` to install the browser-testing library. If Chrome is not at `/usr/bin/google-chrome`, set the `CHROME_PATH` environment setting to the location of your installed Chrome program. This setting tells the test where Chrome is installed. Then run `node browser-test.js`. Installing Playwright beside the test program lets Node find it. The test program writes `Desktop-QA.png` and `Mobile-QA.png` into that copy. These extra programs are for testing only, not for using the tool.

GitHub Actions, GitHub's automatic-check service, runs `node test.js` on Node 22 when the shared header-reading code, its tests or the file controlling those checks changes. It can also be started manually. Browser checks are separate and do not run in that automatic check. This repository does not include a saved test-results file.

What the tool does: read reported header checks on your computer. This is not a tool that independently checks email authenticity or detects misleading emails.

## Licence

The software uses the MIT licence, a named software-use licence. Read its permissions and conditions in [LICENSE](LICENSE).
