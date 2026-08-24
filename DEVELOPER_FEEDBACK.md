# Developer feedback, building AEGIS on Protegrity AI Developer Edition

Optional submission item for the 2026 AI Pipeline Security Challenge. Written from
actually building on the product, not from the docs.

## What worked well

**Public GHCR images with no login is the right call.** `docker compose up -d` on
`data-discovery` and the classifier was answering in under two minutes, no account, no key,
no sales conversation. That is unusual for a data-protection product and it is the single
best thing about the developer experience. I had real classifier output before I had
credentials for anything.

**The classifier earns its place in the pipeline.** My offline stand-in tokenizer is regex
based, so it catches an SSN and an email and cannot see a name sitting in prose. That gap is
asserted as a deliberate xfail in my test suite because I would rather measure it than hide
it. Protegrity's context provider finds `PERSON` at 0.81 in the same sentence. That is a
concrete, demonstrable reason to reach for the product rather than roll your own, and it is
the moment the integration stopped being a checkbox for me.

**Container port 8050 maps to host 8580, which is the SDK's default endpoint.** Small thing,
but it means the quickstart works with zero configuration. Somebody thought about that.

**The API surface is small and honest.** `configure`, `discover`, `find_and_protect`,
`find_and_unprotect`, `find_and_redact`, `securefind`. Six functions, obvious names, and the
protect/unprotect pair is genuinely symmetric. I wrapped the whole thing in one adapter class
with two methods.

## What tripped me up

**1. `find_and_redact()` silently returns the input unchanged if `configure()` was not given
a `named_entity_map`.** This is the one I would fix first. There is no exception, no warning,
no log line. The call succeeds and hands back your original text with the PII still in it. In
a data-protection library that failure mode is dangerous, because the happy path and the
silent-no-op path are indistinguishable to the caller. If someone ships that in a pipeline
they believe is protected, it is not. Raising on a missing map, or logging at WARNING, would
have saved me about an hour and would save someone else a breach.

**2. `appython` is easy to mistake for the Developer Edition path.** Early on I built the
structured-protection path against `appython.create_session().protect()`, which is the
enterprise Application Protector and needs a gateway and policy deployment. It is a different
product. Nothing in the naming makes that obvious, and I had written and tested a whole
adapter before finding out. A line in the DE README saying "if you are here, you want
`protegrity-developer-python`, not `appython`" would prevent that.

**3. Data Discovery and Data Protection have very different access stories, and that is not
signposted.** Discovery is public containers with no account. Protection is a hosted API
needing self-service credentials from a different page. Both are "Developer Edition." I spent
a month believing I was blocked on an access email for the whole product when two thirds of
it was one `docker compose up` away. That was partly my own failure to dig, but a short
"what needs credentials and what does not" table at the top of the org README would have
fixed it instantly.

**4. The SDK logs at INFO by default, one line per detected entity per call.** For a batch job
that is fine. For anything with curated output, or a recorded walkthrough, it interleaves
ahead of your own prints and looks like an error. Defaulting to WARNING and letting callers
opt in would be friendlier.

**5. The credentials email sends the password and the API key in cleartext.** I want to raise
this one carefully, because I am raising it with a data-protection company and I do not mean
it as a cheap shot. The Developer Edition welcome email contains both the account password and
the API key as plain text in the body. That message now sits indefinitely in my mail provider's
storage, in their backups, on every device synced to that mailbox, and in any downstream tool
with mailbox access. It is also the credential set for the service whose entire job is
protecting sensitive values.

The usual pattern here is a one-time link that provisions the secret in a browser session, or
a first-login forced rotation, or at minimum an expiring key with a documented rotation path.
Any of those would remove the standing exposure. I could not find a rotation mechanism in the
docs or the portal.

I would also note the asymmetry, since it is the kind of thing your own customers will notice:
the product tokenizes an SSN so it never sits in plaintext in a vector store, and the onboarding
flow puts the key to that product in plaintext in a Gmail inbox. Closing that loop would make
the developer experience match the pitch.

## What I would want to see

**A local protection option, even a weak one.** Discovery runs entirely on my machine.
Protection is hosted only, which means the tokenization step, the part my whole architecture
depends on, cannot run air-gapped and cannot run offline. For a threat model where the
premise is "assume the boundary is already compromised," a network round trip to tokenize is
an awkward dependency. Even a local dev-only tokenizer with clearly non-production keys would
let people build and test the full pipeline shape without connectivity.

**Token format documentation.** I hardcoded a token recognition regex against my mock and it
would not have matched real Protegrity output. I caught it in an adversarial review of my own
code, but the fix was to route token recognition through the Protector interface rather than
pattern matching. Knowing the guaranteed shape of a token, or being given an `is_token()`
helper, would make that a non-issue.

**Rate and payload limits stated up front.** I found the 10k requests/day and 1MB payload
numbers secondhand rather than in the getting-started path. For anyone sizing an ingest job,
that belongs next to the install instructions.

## Context on my submission

AEGIS assumes the prompt injection succeeds and gates the data instead of the prompt, so that
a successful injection yields tokens rather than people. Protegrity does the detection and the
reversible protection at the ingest boundary. The rest of the architecture, scope-bound
reveal, honeytoken tripwire, hash-chained audit ledger, and outbound action gate, is built on
top of that guarantee.

One note for the record: I registered on July 26, received two confirmations, and never got
Developer Edition access information. Your August 5 email with the submission details also
landed in my spam folder and I found it on the 22nd, which I have written up separately with
the header analysis. Neither is a complaint about the product, and I got there in the end
under my own steam, but if other registrants went quiet you may want to check whether they hit
the same two walls.

Happy to talk about any of this.

Ash Clements
ashclements.dev
