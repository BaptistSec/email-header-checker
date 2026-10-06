# Email header checker

A small, single-file tool that reads the SPF, DKIM and DMARC results recorded in an email's `Authentication-Results` header, and flags a few common warning signs.

Everything runs in your browser. Nothing is uploaded, stored or sent anywhere.

## Use it

Open `index.html` (or the GitHub Pages demo), paste the full headers of a message, and press "Check headers".

- Gmail: open the message, three-dot menu, "Show original".
- Outlook: File, Properties, "Internet headers".

## What it checks

- SPF, DKIM and DMARC results (pass, fail, softfail, none and so on) with the domain each applies to.
- Reply-To domain different from the From domain.
- Return-Path domain different from the From domain (shown as information only, as bulk senders often do this).
- Missing Authentication-Results header or missing mechanisms.

## Limits

It reports what the header says. It does not verify DKIM signatures or look up DNS itself, and a pass does not prove a message is safe. Only trust the topmost `Authentication-Results` header, which your own mail provider added.

## Tests

`header-check.js` holds the same parsing logic as the page. Run `node test.js` to run the test cases.

## Licence

MIT. Written by William Baptist.


Any bugs or suggestions, contact me: baptistsec
