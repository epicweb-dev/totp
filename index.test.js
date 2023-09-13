import assert from 'node:assert'
import { test } from 'node:test'
import base32 from 'thirty-two'
import { generateTOTP, getTOTPAuthUri, verifyTOTP } from './index.js'

test('OTP can be generated and verified', () => {
	const { secret, otp, algorithm, period, digits } = generateTOTP()
	assert.strictEqual(algorithm, 'SHA1')
	assert.strictEqual(period, 30)
	assert.strictEqual(digits, 6)
	const result = verifyTOTP({ otp, secret })
	assert.deepStrictEqual(result, { delta: 0 })
})

test('options can be customized', () => {
	const options = {
		algorithm: 'SHA256',
		period: 60,
		digits: 8,
		secret: base32.encode(Math.random().toString(16).slice(2)).toString(),
		charSet: 'abcdef',
	}
	const { otp, ...config } = generateTOTP(options)
	assert.deepStrictEqual(config, options)
	const result = verifyTOTP({ otp, ...config })
	assert.deepStrictEqual(result, { delta: 0 })
})

test('Verify TOTP within the specified time window', () => {
	const { otp, secret } = generateTOTP()
	const result = verifyTOTP({ otp, secret, window: 0 })
	assert.notStrictEqual(result, null)
})

test('Fail to verify an invalid TOTP', () => {
	const secret = Math.random().toString()
	const tooShortNumber = Math.random().toString().slice(2, 7)
	const result = verifyTOTP({ otp: tooShortNumber, secret })
	assert.strictEqual(result, null)
})

test('Fail to verify TOTP outside the specified time window', async () => {
	const { otp, secret: key } = generateTOTP({ period: 0.0001 })
	await new Promise((resolve) => setTimeout(resolve, 1))
	const result = verifyTOTP({ otp, secret: key })
	assert.strictEqual(result, null)
})

test('Clock drift is handled by window', async () => {
	// super small period
	const { otp, secret: key, period } = generateTOTP({ period: 0.0001 })
	// waiting a tiny bit
	await new Promise((resolve) => setTimeout(resolve, 1))
	// super big window (to accomodate slow machines running this test)
	const result = verifyTOTP({ otp, secret: key, window: 200, period })
	// should still validate
	assert.notDeepStrictEqual(result, null)
})

test('Setting a different period config for generating and verifying will fail', () => {
	const desiredPeriod = 60
	const { otp, secret, period } = generateTOTP({
		period: desiredPeriod,
	})
	assert.strictEqual(period, desiredPeriod)
	const result = verifyTOTP({ otp, secret, period: period + 1 })
	assert.strictEqual(result, null)
})

test('Setting a different algo config for generating and verifying will fail', () => {
	const desiredAlgo = 'SHA512'
	const { otp, secret, algorithm } = generateTOTP({
		algorithm: desiredAlgo,
	})
	assert.strictEqual(algorithm, desiredAlgo)
	const result = verifyTOTP({ otp, secret, algorithm: 'SHA1' })
	assert.strictEqual(result, null)
})

test('Generating and verifying also works with the algorithm name alias', () => {
	const desiredAlgo = 'SHA1'
	const { otp, secret, algorithm } = generateTOTP({
		algorithm: desiredAlgo,
	})
	assert.strictEqual(algorithm, desiredAlgo)

	const result = verifyTOTP({ otp, secret, algorithm: 'sha1' })
	assert.notStrictEqual(result, null)
})

test('Charset defaults to numbers', () => {
	const { otp } = generateTOTP()
	assert.match(otp, /^[0-9]+$/)
})

test('Charset can be customized', () => {
	const { otp } = generateTOTP({ charSet: 'abcdef' })
	assert.match(otp, /^[abcdef]+$/)
})

test('OTP Auth URI can be generated', () => {
	const { otp: _otp, secret, ...totpConfig } = generateTOTP()
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
