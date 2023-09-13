<div>
  <h1 align="center"><a href="https://npm.im/@epic-web/totp">🕰 @epic-web/totp</a></h1>
  <strong>
    Support Two Factor Authentication (2FA) in your application with ease.
  </strong>
  <p>
    Create and verify cryptographically secure Time-based One-time Passwords
    (TOTP) using the HMAC-based One-time Password (HOTP) algorithm.
  </p>
</div>

```
npm install @epic-web/totp
```

<div align="center">
  <a
    alt="Epic Web logo"
    href="https://www.epicweb.dev"
  >
    <img
      width="300px"
      src="https://github-production-user-asset-6210df.s3.amazonaws.com/1500684/257881576-fd66040b-679f-4f25-b0d0-ab886a14909a.png"
    />
  </a>
</div>

<hr />

<!-- prettier-ignore-start -->
[![Build Status][build-badge]][build]
[![MIT License][license-badge]][license]
[![Code of Conduct][coc-badge]][coc]
<!-- prettier-ignore-end -->

## The problem

You want to support 2FA clients or generate safe one-time passwords to otherwise
verify your users.

## This solution

This was copy/paste/modified/tested from [notp](https://npm.im/notp) (MIT)

The primary motivation was to support a more secure algorithm than `SHA1`
(though Google Authenticator only supports `SHA1`, longer-lived OTPs should use
a more secure algorithm). The maintainer has not actively responded to issues or
pull requests in years.

Some improvements were made to modernize the code (which was last published
in 2014) and improve the API. But the core algorithm is unchanged.

## Terms

- **OTP**: One Time Password
- **HOTP**: HMAC-based One Time Password
- **TOTP**: Time-based One Time Password

The **TOTP** is what we typically use for verification codes. This can be used
for 2FA (two-factor authentication), but also used for email verification,
password reset, etc.

## Usage

This package exports three methods:

- `generateTOTP` - This generates the OTP and returns the config used to
  generate it.
- `verifyTOTP` - This verifies the OTP against the config used to generate it.
- `getTOTPAuthUri` - This generates a URI that can be used to add the OTP to an
  authenticator app.

### 2FA code

Here's the typical process for generating a 2FA auth URI (which the user can add
to their authenticator app).

```js
import { generateTOTP, getTOTPAuthUri, verifyTOTP } from '@epic-web/totp'

// Here's how to use the default config. All the options are returned:
const { secret, period, digits, algorithm } = generateTOTP()
const otpUri = getTOTPAuthUri({
	period,
	digits,
	algorithm,
	secret,
	accountName: user.email,
	issuer: 'Your App Name',
})
// check docs below for customization options.

// optional, but recommended: import * as QRCode from 'qrcode'
// const qrCode = await QRCode.toDataURL(otpUri)

// now you can display the QR code and the URI to the user and let them enter
// their code from their authenticator app.
// however you get the code from the user, do it:
const code = await getCodeFromUser()

// now verify the code:
const isValid = verifyTOTP({ otp: code, secret, period, digits, algorithm })

// if it's valid, save the secret, period, digits, and algorithm to the database
// along with who it belongs to and use this info to verify the user when they
// login or whatever.
```

### Verification of email/phone number ownership

Here's the typical process for a one-time verification of a user's email/phone
number/etc.:

```js
import { generateTOTP, verifyTOTP } from '@epic-web/totp'

const { otp, secret, digits, period, algorithm } = generateTOTP({
	algorithm: 'SHA256', // more secure algorithm should be used with longer-lived OTPs
	period: 10 * 60, // 10 minutes
})

await sendOtpToUser({
	email: user.email,
	otp,
	secret,
	digits,
	period,
	algorithm,
})
await saveVerificationToDatabase({
	secret,
	digits,
	period,
	algorithm,
	target: user.email,
})

// when the user gives you the code (however you do that):
const code = await getCodeFromUser()

// now verify the code:
const userCodeConfig = await getVerificationFromDatabase({
	target: user.email,
})
const isValid = verifyTOTP({ otp: code, ...userCodeConfig })

if (isValid) {
	await deleteVerificationFromDatabase({ target: user.email })
	// allow the user to proceed
} else {
	// show an error
}
```

## Customizable Character Set for Increased Security

### Why Charset Matters

When it comes to security, every bit of entropy counts. Entropy measures the
unpredictability and in turn the security of your OTPs. The traditional TOTP
setup often employs a 6-digit numerical code, providing a million (10^6)
combinations. This is the default behaviour for this implementation. While that
is robust, there's room for improvement.

By introducing a customizable character set feature, you can exponentially
increase the entropy of the OTPs, making them much more secure against
brute-force attacks. For example, if you extend your character set to include 26
uppercase letters and 10 digits, a 6-character OTP would have 36^6 = 2.1 billion
combinations. When paired with rate-limiting mechanisms, this configuration
becomes practically impervious to brute-force attacks.

### Potential for Main Form of Authentication

With this added complexity, TOTPs can, in theory, be used as the primary form of
authentication, rather than just a second factor. This is particularly useful
for applications requiring heightened security.

### Usage with Custom Character Set

In addition to the existing options, you can specify a charSet in both
`generateTOTP` and `verifyTOTP`.

Here's how you can generate an OTP with a custom character set:

```js
import { generateTOTP, verifyTOTP } from '@epic-web/totp'

const { otp, secret, period, digits, algorithm, charSet } = generateTOTP({
	charSet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', // custom character set
})

// Remember to save the charSet to your database as well.

// To verify
const isValid = verifyTOTP({
	otp,
	secret,
	period,
	digits,
	algorithm,
	charSet,
})
```

Just as an aside, you probably want to exclude the letter O and the number 0 to
make it easier for users to enter the code.

## API

This library is built with `jsdoc`, so hopefully your editor supports that and
will show you all this stuff, but just in case, here's that:

### `generateTOTP`

```js
/**
 * Creates a time-based one-time password (TOTP). This handles creating a random
 * secret (base32 encoded), and generating a TOTP for the current time. As a
 * convenience, it also returns the config options used to generate the TOTP.
 *
 * @param {Object} [options] Configuration options for the TOTP.
 * @param {number} [options.period=30] The number of seconds for the OTP to be
 * valid. Defaults to 30.
 * @param {number} [options.digits=6] The length of the OTP. Defaults to 6.
 * @param {string} [options.algorithm='SHA1'] The algorithm to use. Defaults to
 * SHA1.
 * @param {string} [options.secret] The secret to use for the TOTP. It should be
 * base32 encoded (you can use https://npm.im/thirty-two). Defaults to a random
 * secret: base32.encode(crypto.randomBytes(10)).toString().
 * @param {string} [options.charSet='0123456789'] - The character set to use, defaults to the numbers 0-9.
 * @returns {{otp: string, secret: string, period: number, digits: number, algorithm: string, charSet: string}}
 * The OTP, secret, and config options used to generate the OTP.
 */
```

### `verifyTOTP`

```js
/**
 * Verifies a time-based one-time password (TOTP). This handles decoding the
 * secret (base32 encoded), and verifying the OTP for the current time.
 *
 * @param {Object} options The otp, secret, and configuration options for the
 * TOTP.
 * @param {string} options.otp The OTP to verify.
 * @param {string} options.secret The secret to use for the TOTP.
 * @param {number} [options.period] The number of seconds for the OTP to be valid.
 * @param {number} [options.digits] The length of the OTP.
 * @param {string} [options.algorithm] The algorithm to use.
 * @param {string} [options.charSet] The character set to use, defaults to the numbers 0-9.
 * @param {number} [options.window] The number of OTPs to check before and after
 * the current OTP. Defaults to 1.
 *
 * @returns {{delta: number}|null} an object with "delta" which is the delta
 * between the current OTP and the OTP that was verified, or null if the OTP is
 * invalid.
 */
```

### `getTOTPAuthUri`

```js
/**
 * Generates a otpauth:// URI which you can use to generate a QR code or users
 * can manually enter into their password manager.
 *
 * @param {Object} options Configuration options for the TOTP Auth URI.
 * @param {number} options.period The number of seconds for the OTP to be valid.
 * @param {number} options.digits The length of the OTP.
 * @param {string} options.algorithm The algorithm to use.
 * @param {string} options.secret The secret to use for the TOTP Auth URI.
 * @param {string} options.accountName A way to uniquely identify this Auth URI
 * (in case they have multiple of these).
 * @param {string} options.issuer The issuer to use for the TOTP Auth URI.
 *
 * @returns {string} The OTP Auth URI
 */
```

## License

MIT

<!-- prettier-ignore-start -->
[build-badge]: https://img.shields.io/github/actions/workflow/status/epicweb-dev/totp/release.yml?branch=main&logo=github&style=flat-square
[build]: https://github.com/epicweb-dev/totp/actions?query=workflow%3Arelease
[license-badge]: https://img.shields.io/badge/license-MIT%20License-blue.svg?style=flat-square
[license]: https://github.com/epicweb-dev/totp/blob/main/LICENSE
[coc-badge]: https://img.shields.io/badge/code%20of-conduct-ff69b4.svg?style=flat-square
[coc]: https://kentcdodds.com/conduct
<!-- prettier-ignore-end -->
