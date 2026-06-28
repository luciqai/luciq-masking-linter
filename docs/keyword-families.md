# Keyword families — reference guide

This is **human documentation only**. The linter does *not* read this file; it ships
its own copy of the built-in families in code (`BUILTIN_FAMILIES` in
`luciq_masking_linter.py`). This guide exists so that everyone uses consistent family
names when adding custom keywords to the `pii_masking.keywords` section of `luciq.yml`.

A "family" is a category of PII. Each family has:
- a built-in keyword regex the linter matches against field/binding names, and
- a default severity that the compliance level can promote to a hard fail.

Source of truth for *what counts as PII* is the Luciq PII Masking Reference (the PDF)
and the live docs at https://docs.luciq.ai/product-guides-and-integrations/product-guides/luciq-pii-masking.

## Built-in families

| Family | Covers | Example name matches | Hard-fail by default under |
|---|---|---|---|
| `card` | Cardholder data — PAN, CVV, bank account, IBAN | `cardNumber`, `pan`, `cvv`, `iban`, `accountNumber` | none, soc2, **pci** (no waiver), gdpr, hipaa |
| `ssn` | National / tax / social-security identifiers | `ssn`, `nationalId`, `taxId` | all levels |
| `credentials` | Passwords, PINs, OTPs, secrets, tokens | `password`, `pin`, `otp`, `apiKey`, `accessToken` | all levels |
| `health` | PHI — diagnosis, MRN, medication, patient data | `diagnosis`, `mrn`, `medication`, `patientId` | **hipaa** |
| `dob` | Date of birth | `dob`, `birthDate`, `dateOfBirth` | gdpr, hipaa |
| `email` | Email addresses | `email`, `userEmail`, `emailAddress` | gdpr, hipaa |
| `phone` | Phone / mobile numbers | `phone`, `msisdn`, `mobileNumber` | gdpr, hipaa |
| `address` | Postal / home address | `homeAddress`, `street`, `postalCode` | gdpr, hipaa |
| `name` | Person names (tuned to avoid `className`, `fileName`) | `firstName`, `lastName`, `patientName` | gdpr, hipaa |
| `input` | Synthetic: any text input box with no recognizable name | every `EditText` / `TextField` / `SecureField` | gdpr, hipaa |

Candidacy is **name-driven** by default: a text input (`EditText` / `TextField` /
`SecureField`) is flagged only when its name matches one of the named families above —
never merely for being an input. A generically-named input (e.g.
`TextField("", text: $value)`) is **not** a candidate under `none`/`soc2`/`pci`, so
widen recall there by adding stems to `pii_masking.keywords`.

The `input` family is the one exception, and it is active **only under GDPR/HIPAA**,
where masking all user input is mandatory: on those two levels *every* text input is a
candidate regardless of name. PII inputs are normally cleared in bulk by configuring
auto-mask `TEXT_INPUTS`.

## Compliance dial — what each level changes

The level does not add new checks; it turns dials on the existing ones.

| Level | Promotes to hard fail | Also requires |
|---|---|---|
| `none` | card, ssn, credentials | — |
| `soc2` | card, ssn, credentials | auto-mask configured |
| `pci` | card, ssn, credentials | card waivers forbidden |
| `gdpr` | + email, phone, name, address, dob, input | consent gating before Session Replay |
| `hipaa` | all families | `MEDIA` in auto-mask + consent gating |

### Full severity matrix (`unmasked-field`)

Severity of a field that **is** a candidate and is **not** masked or waived. `fail`
blocks under `--mode enforce`; `warn` only reports; `—` means the field is not a
candidate at that level.

| Family | none | soc2 | pci | gdpr | hipaa |
|---|:--:|:--:|:--:|:--:|:--:|
| `card` | fail | fail | fail | fail | fail |
| `ssn` | fail | fail | fail | fail | fail |
| `credentials` | fail | fail | fail | fail | fail |
| `health` | warn | warn | warn | warn | **fail** |
| `dob` | warn | warn | warn | **fail** | fail |
| `email` | warn | warn | warn | **fail** | fail |
| `phone` | warn | warn | warn | **fail** | fail |
| `address` | warn | warn | warn | **fail** | fail |
| `name` | warn | warn | warn | **fail** | fail |
| `input` *(unnamed text input)* | — | — | — | **fail** | fail |
| *custom family* (e.g. `account`) | warn | warn | warn | warn | warn |

> **Custom families are always `warn`** — even under HIPAA. Severity is only promoted
> for families a preset lists explicitly, and an invented name (`account`, `member`, …)
> is in none of them. To make an app-specific keyword **block**, nest its stem under a
> built-in family (`ssn`, `credentials`, …) rather than a new family name.

## Adding a custom family

If your app names PII in a way the built-ins miss (e.g. `memberFiscalCode` for SSN),
add the keyword stem under the closest family in `luciq.yml`:

```yaml
pii_masking:
  keywords:
    ssn: [fiscalCode]      # now any field containing "fiscalCode" is treated as ssn
```

Prefer an existing family name so compliance severity applies. Only invent a new
family name (e.g. `member`) when none of the built-ins fit; a custom family is
treated as generic PII (hard-fail under gdpr/hipaa, warn otherwise).

> Keep custom keywords as **stems**, never exact field names. Matching is
> case-insensitive and separator-insensitive: the word boundaries in a stem match
> camelCase, snake_case, kebab-case, or spaced spellings alike. So `fiscalCode`
> catches `userFiscalCode`, `fiscal_code`, `fiscal-code`, and `fiscalCodeNumber`;
> a frozen exact name would miss the next variant a developer writes.
