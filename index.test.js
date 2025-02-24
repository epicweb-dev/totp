import assert from 'node:assert'
import { test } from 'node:test'
import base32Encode from 'base32-encode'
import { generateTOTP, getTOTPAuthUri, verifyTOTP } from './index.js'

test('OTP can be generated and verified', async () => {
	const { secret, otp, algorithm, period, digits } = await generateTOTP()

	assert.strictEqual(algorithm, 'SHA-1')
	assert.strictEqual(period, 30)
	assert.strictEqual(digits, 6)
	const result = await verifyTOTP({ otp, secret })
	assert.deepStrictEqual(result, { delta: 0 })
})

test('options can be customized', async () => {
	const options = {
		algorithm: 'SHA-256',
		period: 60,
		digits: 8,
		secret: base32Encode(
			new TextEncoder().encode(Math.random().toString(16).slice(2)),
			'RFC4648'
		).toString(),
		charSet: 'abcdef',
	}
	const { otp, ...config } = await generateTOTP(options)
	assert.deepStrictEqual(config, options)
	const result = await verifyTOTP({ otp, ...config })
	assert.deepStrictEqual(result, { delta: 0 })
})

test('Verify TOTP within the specified time window', async () => {
	const { otp, secret } = await generateTOTP()
	const result = await verifyTOTP({ otp, secret, window: 0 })
	assert.notStrictEqual(result, null)
})

test('Fail to verify an invalid TOTP', async () => {
	const secret = Math.random().toString()
	const tooShortNumber = Math.random().toString().slice(2, 7)
	const result = await verifyTOTP({ otp: tooShortNumber, secret })
	assert.strictEqual(result, null)
})

test('Fail to verify TOTP outside the specified time window', async () => {
	const { otp, secret: key } = await generateTOTP({ period: 0.0001 })
	await new Promise((resolve) => setTimeout(resolve, 1))
	const result = await verifyTOTP({ otp, secret: key })
	assert.strictEqual(result, null)
})

test('Clock drift is handled by window', async () => {
	// super small period
	const { otp, secret: key, period } = await generateTOTP({ period: 0.0001 })
	// waiting a tiny bit
	await new Promise((resolve) => setTimeout(resolve, 1))
	// super big window (to accomodate slow machines running this test)
	const result = await verifyTOTP({ otp, secret: key, window: 200, period })
	// should still validate
	assert.notDeepStrictEqual(result, null)
})

test('Setting a different period config for generating and verifying will fail', async () => {
	const desiredPeriod = 60
	const { otp, secret, period } = await generateTOTP({
		period: desiredPeriod,
	})
	assert.strictEqual(period, desiredPeriod)
	const result = await verifyTOTP({ otp, secret, period: period + 1 })
	assert.strictEqual(result, null)
})

test('Setting a different algo config for generating and verifying will fail', async () => {
	const desiredAlgo = 'SHA-512'
	const { otp, secret, algorithm } = await generateTOTP({
		algorithm: desiredAlgo,
	})
	assert.strictEqual(algorithm, desiredAlgo)
	const result = await verifyTOTP({ otp, secret, algorithm: 'SHA-1' })
	assert.strictEqual(result, null)
})

test('Generating and verifying also works with the algorithm name alias', async () => {
	const desiredAlgo = 'SHA-1'
	const { otp, secret, algorithm } = await generateTOTP({
		algorithm: desiredAlgo,
	})
	assert.strictEqual(algorithm, desiredAlgo)

	const result = await verifyTOTP({ otp, secret, algorithm: 'sha-1' })
	assert.notStrictEqual(result, null)
})

test('Charset defaults to numbers', async () => {
	const { otp } = await generateTOTP()
	assert.match(otp, /^[0-9]+$/)
})

test('Charset can be customized', async () => {
	const { otp } = await generateTOTP({ charSet: 'abcdef' })
	assert.match(otp, /^[abcdef]+$/)
})

test('OTP Auth URI can be generated', async () => {
	const { otp: _otp, secret, ...totpConfig } = await generateTOTP()
	const issuer = Math.random().toString(16).slice(2)
	const accountName = Math.random().toString(16).slice(2)
	const uri = getTOTPAuthUri({
		issuer,
		accountName,
		secret,
		...totpConfig,
	})
	assert.match(uri, /^otpauth:\/\/totp\/(.*)\?/)
})

test('OTP with digits > 6 should not pad with first character of charSet', async () => {
	const charSet = 'ABCDEFGHIJKLMNPQRSTUVWXYZ123456789'
	const iterations = 100
	let allOtps = []

	for (let i = 0; i < iterations; i++) {
		const { otp } = await generateTOTP({
			algorithm: 'SHA-256',
			charSet,
			digits: 12,
			period: 60 * 30,
		})
		allOtps.push(otp)

		// Verify the OTP only contains characters from the charSet
		assert.match(
			otp,
			new RegExp(`^[${charSet}]{12}$`),
			'OTP should be 12 characters from the charSet'
		)

		// The first 6 characters should not all be 'A' (first char of charSet)
		const firstSixChars = otp.slice(0, 6)
		assert.notStrictEqual(
			firstSixChars,
			'A'.repeat(6),
			'First 6 characters should not all be A'
		)
	}
})
