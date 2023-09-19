/**
 * This was copy/paste/modified/tested from https://npm.im/notp (MIT)
 */
import * as crypto from 'crypto'

/**
 * @type {{ encode: (data: string | import('buffer').Buffer) => string, decode: (data: string) => import('buffer').Buffer }}
 */
import * as base32 from 'thirty-two'

// SHA1 is not secure, but in the context of TOTPs, it's unrealistic to expect
// security issues. Also, it's the default for compatibility with OTP apps.
// That said, if you're acting the role of both client and server and your TOTP
// is longer lived, you can definitely use a more secure algorithm like SHA256.
// Learn more: https://www.rfc-editor.org/rfc/rfc4226#page-25 (B.1. SHA-1 Status)
const DEFAULT_ALGORITHM = 'SHA1'
const DEFAULT_CHAR_SET = '0123456789'
const DEFAULT_DIGITS = 6
const DEFAULT_WINDOW = 1
const DEFAULT_PERIOD = 30

/**
 * Generates a HMAC-based One Time Password (HOTP) using the provided secret and
 * configuration options.
 *
 * @param {Buffer} secret - The secret used to generate the HOTP.
 * @param {Object} options - The configuration options for the HOTP.
 * @param {number} [options.counter=0] - The counter value to use for the HOTP.
 * Defaults to 0.
 * @param {number} [options.digits=6] - The number of digits to use for the
 * HOTP. Defaults to 6.
 * @param {string} [options.algorithm='SHA1'] - The algorithm to use for the
 * HOTP. Defaults to 'SHA1'.
 * @param {string} [options.charSet='0123456789'] - The character set to use, defaults to the numbers 0-9.
 * @returns {string} The generated HOTP.
 */
function generateHOTP(
	secret,
	{
		counter = 0,
		digits = DEFAULT_DIGITS,
		algorithm = DEFAULT_ALGORITHM,
		charSet = DEFAULT_CHAR_SET,
	} = {}
) {
	const byteCounter = Buffer.from(intToBytes(counter))
	const hmac = crypto.createHmac(algorithm, secret)
	const digest = hmac.update(byteCounter).digest('hex')
	const hashBytes = hexToBytes(digest)
	const offset = hashBytes[19] & 0xf
	let hotpVal =
		((hashBytes[offset] & 0x7f) << 24) |
		((hashBytes[offset + 1] & 0xff) << 16) |
		((hashBytes[offset + 2] & 0xff) << 8) |
		(hashBytes[offset + 3] & 0xff)

	let hotp = ''
	for (let i = 0; i < digits; i++) {
		hotp = charSet.charAt(hotpVal % charSet.length) + hotp
		hotpVal = Math.floor(hotpVal / charSet.length)
	}

	return hotp
}

/**
 * Verifies a HMAC-based One Time Password (HOTP) using the provided OTP and
 * configuration options.
 *
 * @param {string} otp - The OTP to verify.
 * @param {Buffer} secret - The secret used to generate the HOTP.
 * @param {Object} options - The configuration options for the HOTP.
 * @param {number} [options.counter=0] - The counter value to use for the HOTP.
 * Defaults to 0.
 * @param {number} [options.digits=6] - The number of digits to use for the
 * HOTP. Defaults to 6.
 * @param {string} [options.algorithm='SHA1'] - The algorithm to use for the
 * HOTP. Defaults to 'SHA1'.
 * @param {string} [options.charSet='0123456789'] - The character set to use, defaults to the numbers 0-9.
 * @param {number} [options.window=1] - The number of counter values to check
 * before and after the current counter value. Defaults to 1.
 * @returns {{delta: number}|null} An object with the `delta` property
 * indicating the number of counter values between the current counter value and
 * the verified counter value, or `null` if the OTP could not be verified.
 */
function verifyHOTP(
	otp,
	secret,
	{
		counter = 0,
		digits = DEFAULT_DIGITS,
		algorithm = DEFAULT_ALGORITHM,
		charSet = DEFAULT_CHAR_SET,
		window = DEFAULT_WINDOW,
	} = {}
) {
	for (let i = counter - window; i <= counter + window; ++i) {
		if (
			generateHOTP(secret, { counter: i, digits, algorithm, charSet }) === otp
		) {
			return { delta: i - counter }
		}
	}
	return null
}

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
 * @param {string} [options.charSet='0123456789'] - The character set to use, defaults to the numbers 0-9.
 * @param {string} [options.secret] The secret to use for the TOTP. It should be
 * base32 encoded (you can use https://npm.im/thirty-two). Defaults to a random
 * secret: base32.encode(crypto.randomBytes(10)).toString().
 * @returns {{otp: string, secret: string, period: number, digits: number, algorithm: string, charSet: string}}
 * The OTP, secret, and config options used to generate the OTP.
 */
export function generateTOTP({
	period = DEFAULT_PERIOD,
	digits = DEFAULT_DIGITS,
	algorithm = DEFAULT_ALGORITHM,
	secret = base32.encode(crypto.randomBytes(10)).toString(),
	charSet = DEFAULT_CHAR_SET,
} = {}) {
	const otp = generateHOTP(base32.decode(secret), {
		counter: getCounter(period),
		digits,
		algorithm,
		charSet,
	})

	return { otp, secret, period, digits, algorithm, charSet }
}

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
export function getTOTPAuthUri({
	period,
	digits,
	algorithm,
	secret,
	accountName,
	issuer,
}) {
	const params = new URLSearchParams({
		secret,
		issuer,
		algorithm,
		digits: digits.toString(),
		period: period.toString(),
	})

	const escapedIssuer = encodeURIComponent(issuer)
	const escapedAccountName = encodeURIComponent(accountName)
	const label = `${escapedIssuer}:${escapedAccountName}`

	return `otpauth://totp/${label}?${params.toString()}`
}

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
 * @param {string} [options.charSet] - The character set to use, defaults to the numbers 0-9.
 * @param {number} [options.window] The number of OTPs to check before and after
 * the current OTP. Defaults to 1.
 *
 * @returns {{delta: number}|null} an object with "delta" which is the delta
 * between the current OTP and the OTP that was verified, or null if the OTP is
 * invalid.
 */
export function verifyTOTP({
	otp,
	secret,
	period,
	digits,
	algorithm,
	charSet,
	window = DEFAULT_WINDOW,
}) {
	return verifyHOTP(otp, base32.decode(secret), {
		counter: getCounter(period),
		digits,
		window,
		algorithm,
		charSet,
	})
}

/**
 * Converts a number to a byte array.
 *
 * @param {number} num The number to convert to a byte array.
 * @returns {number[]} The byte array representation of the number.
 */
function intToBytes(num) {
	const buffer = Buffer.alloc(8)
	// eslint-disable-next-line no-undef
	buffer.writeBigInt64BE(BigInt(num))
	return [...buffer]
}

/**
 * Converts a hexadecimal string to a byte array.
 *
 * @param {string} hex The hexadecimal string to convert to a byte array.
 * @returns {number[]} The byte array representation of the hexadecimal string.
 */
function hexToBytes(hex) {
	return [...Buffer.from(hex, 'hex')]
}

/**
 * Calculates the current counter value for the TOTP based on the current time
 * and the specified period.
 *
 * @param {number} [period=30] The number of seconds for the OTP to be valid.
 * @returns {number} The current counter value for the TOTP.
 */
function getCounter(period = DEFAULT_PERIOD) {
	const now = new Date().getTime()
	const counter = Math.floor(now / 1000 / period)
	return counter
}
