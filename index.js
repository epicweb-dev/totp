/**
 * This was copy/paste/modified/tested from https://npm.im/notp (MIT)
 */
import base32Encode from 'base32-encode'
import base32Decode from 'base32-decode'

/**
 * @typedef {'SHA-1' | 'SHA-256' | 'SHA-386' | 'SHA-512' | string & {}} HashAlgorithm
 *
 * For all available algorithms, refer to the following:
 * https://developer.mozilla.org/en-US/docs/Web/API/HmacImportParams#hash
 */

// SHA-1 is not secure, but in the context of TOTPs, it's unrealistic to expect
// security issues. Also, it's the default for compatibility with OTP apps.
// That said, if you're acting the role of both client and server and your TOTP
// is longer lived, you can definitely use a more secure algorithm like SHA-256.
// Learn more: https://www.rfc-editor.org/rfc/rfc4226#page-25 (B.1. SHA-1 Status)
const DEFAULT_ALGORITHM = 'SHA-1'
const DEFAULT_CHAR_SET = '0123456789'
const DEFAULT_DIGITS = 6
const DEFAULT_WINDOW = 1
const DEFAULT_PERIOD = 30

/**
 * Generates a HMAC-based One Time Password (HOTP) using the provided secret and
 * configuration options.
 *
 * @param {ArrayBuffer} secret - The secret used to generate the HOTP.
 * @param {Object} options - The configuration options for the HOTP.
 * @param {number} [options.counter=0] - The counter value to use for the HOTP.
 * Defaults to 0.
 * @param {number} [options.digits=6] - The number of digits to use for the
 * HOTP. Defaults to 6.
 * @param {HashAlgorithm} [options.algorithm='SHA-1'] - The algorithm to use for the
 * HOTP. Defaults to 'SHA-1'.
 * @param {string} [options.charSet='0123456789'] - The character set to use, defaults to the numbers 0-9.
 * @returns {Promise<string>} The generated HOTP.
 */
async function generateHOTP(
	secret,
	{
		counter = 0,
		digits = DEFAULT_DIGITS,
		algorithm = DEFAULT_ALGORITHM,
		charSet = DEFAULT_CHAR_SET,
	} = {}
) {
	const byteCounter = intToBytes(counter)
	const key = await crypto.subtle.importKey(
		'raw',
		secret,
		{ name: 'HMAC', hash: algorithm },
		false,
		['sign']
	)
	const signature = await crypto.subtle.sign('HMAC', key, byteCounter)
	const hashBytes = new Uint8Array(signature)

	// Use more bytes for longer OTPs
	const bytesNeeded = Math.ceil((digits * Math.log2(charSet.length)) / 8)
	const offset = hashBytes[hashBytes.length - 1] & 0xf

	// Convert bytes to BigInt for larger numbers
	let hotpVal = 0n
	for (let i = 0; i < Math.min(bytesNeeded, hashBytes.length - offset); i++) {
		hotpVal = (hotpVal << 8n) | BigInt(hashBytes[offset + i])
	}

	let hotp = ''
	const charSetLength = BigInt(charSet.length)
	for (let i = 0; i < digits; i++) {
		hotp = charSet.charAt(Number(hotpVal % charSetLength)) + hotp
		hotpVal = hotpVal / charSetLength
	}

	return hotp
}

/**
 * Verifies a HMAC-based One Time Password (HOTP) using the provided OTP and
 * configuration options.
 *
 * @param {string} otp - The OTP to verify.
 * @param {ArrayBuffer} secret - The secret used to generate the HOTP.
 * @param {Object} options - The configuration options for the HOTP.
 * @param {number} [options.counter=0] - The counter value to use for the HOTP.
 * Defaults to 0.
 * @param {number} [options.digits=6] - The number of digits to use for the
 * HOTP. Defaults to 6.
 * @param {HashAlgorithm} [options.algorithm='SHA-1'] - The algorithm to use for the
 * HOTP. Defaults to 'SHA-1'.
 * @param {string} [options.charSet='0123456789'] - The character set to use, defaults to the numbers 0-9.
 * @param {number} [options.window=1] - The number of counter values to check
 * before and after the current counter value. Defaults to 1.
 * @returns {Promise<{delta: number}|null>} An object with the `delta` property
 * indicating the number of counter values between the current counter value and
 * the verified counter value, or `null` if the OTP could not be verified.
 */
async function verifyHOTP(
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
			(await generateHOTP(secret, {
				counter: i,
				digits,
				algorithm,
				charSet,
			})) === otp
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
 * @param {HashAlgorithm} [options.algorithm='SHA-1'] The algorithm to use. Defaults to
 * SHA-1.
 * @param {string} [options.charSet='0123456789'] - The character set to use, defaults to the numbers 0-9.
 * @param {string} [options.secret] The secret to use for the TOTP. It should be
 * base32 encoded (you can use https://npm.im/thirty-two). Defaults to a random
 * secret: base32Encode(crypto.getRandomValues(new Uint8Array(10)), 'RFC4648').
 * @returns {Promise<{otp: string, secret: string, period: number, digits: number, algorithm: string, charSet: string}>}
 * The OTP, secret, and config options used to generate the OTP.
 */
export async function generateTOTP({
	period = DEFAULT_PERIOD,
	digits = DEFAULT_DIGITS,
	algorithm = DEFAULT_ALGORITHM,
	secret = base32Encode(crypto.getRandomValues(new Uint8Array(10)), 'RFC4648'),
	charSet = DEFAULT_CHAR_SET,
} = {}) {
	const otp = await generateHOTP(base32Decode(secret, 'RFC4648'), {
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
 * @param {HashAlgorithm} options.algorithm The algorithm to use.
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
 * @param {HashAlgorithm} [options.algorithm] The algorithm to use.
 * @param {string} [options.charSet] - The character set to use, defaults to the numbers 0-9.
 * @param {number} [options.window] The number of OTPs to check before and after
 * the current OTP. Defaults to 1.
 *
 * @returns {Promise<{delta: number}|null>} an object with "delta" which is the delta
 * between the current OTP and the OTP that was verified, or null if the OTP is
 * invalid.
 */
export async function verifyTOTP({
	otp,
	secret,
	period,
	digits,
	algorithm,
	charSet,
	window = DEFAULT_WINDOW,
}) {
	let decodedSecret
	try {
		decodedSecret = base32Decode(secret, 'RFC4648')
	} catch (error) {
		// If the secret is invalid, return null
		return null
	}

	return verifyHOTP(otp, new Uint8Array(decodedSecret), {
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
 * @returns {Uint8Array} The byte array representation of the number.
 */
function intToBytes(num) {
	const arr = new Uint8Array(8)
	for (let i = 7; i >= 0; i--) {
		arr[i] = num & 0xff
		num = num >> 8
	}
	return arr
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
