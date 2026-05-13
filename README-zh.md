<div>
  <h1 align="center"><a href="https://npm.im/@epic-web/totp">🕰 @epic-web/totp</a></h1>
  <strong>
    轻松在您的应用中支持双因素认证 (2FA)。
  </strong>
  <p>
    使用基于 HMAC 的一次性密码 (HOTP) 算法创建和验证加密安全的基于时间的一次性密码 (TOTP)。
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

## 问题

您希望在应用中支持 2FA 客户端，或生成安全的一次性密码来验证您的用户。

## 解决方案

本项目从 [notp](https://npm.im/notp)（MIT 许可证）复制/粘贴/修改/测试而来。

主要动机是支持比 `SHA-1` 更安全的算法（尽管 Google Authenticator 仅支持 `SHA-1`，但有效期较长的 OTP 应使用更安全的算法）。该维护者多年来未积极回应 issue 或 pull request。

对代码进行了一些改进以使其现代化（该代码上次发布于 2014 年）并改进了 API。但核心算法保持不变。

## 术语

- **OTP**：一次性密码 (One Time Password)
- **HOTP**：基于 HMAC 的一次性密码 (HMAC-based One Time Password)
- **TOTP**：基于时间的一次性密码 (Time-based One Time Password)

**TOTP** 是我们通常用于验证码的方式。它可以用于 2FA（双因素认证），也可用于电子邮件验证、密码重置等。

## 用法

本包导出三个方法：

- `generateTOTP` - 生成 OTP 并返回用于生成它的配置。
- `verifyTOTP` - 根据用于生成 OTP 的配置验证 OTP。
- `getTOTPAuthUri` - 生成一个 URI，可用于将 OTP 添加到认证器应用。

### 2FA 验证码

以下是生成 2FA 认证 URI 的典型流程（用户可以将其添加到认证器应用）。

```js
import { generateTOTP, getTOTPAuthUri, verifyTOTP } from '@epic-web/totp'

// 以下是使用默认配置的方式。所有选项都会返回：
const { secret, period, digits, algorithm } = await generateTOTP()
const otpUri = getTOTPAuthUri({
	period,
	digits,
	algorithm,
	secret,
	accountName: user.email,
	issuer: 'Your App Name',
})
// 请参阅下方文档了解自定义选项。

// 可选但推荐：import * as QRCode from 'qrcode'
// const qrCode = await QRCode.toDataURL(otpUri)

// 现在您可以向用户展示二维码和 URI，让他们从认证器应用中输入验证码。
// 无论您如何从用户获取验证码，请执行以下操作：
const code = await getCodeFromUser()

// 现在验证验证码：
const isValid = await verifyTOTP({ otp: code, secret, period, digits, algorithm })

// 如果验证通过，请将 secret、period、digits 和 algorithm 保存到数据库，
// 并关联到相应用户，在用户登录时使用这些信息进行验证。
```

### 电子邮件/电话号码所有权验证

以下是用于一次性验证用户电子邮件/电话号码等的典型流程：

```js
import { generateTOTP, verifyTOTP } from '@epic-web/totp'

const { otp, secret, digits, period, algorithm } = await generateTOTP({
	algorithm: 'SHA-256', // 有效期较长的 OTP 应使用更安全的算法
	period: 10 * 60, // 10 分钟
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

// 当用户提交验证码时（无论您如何获取）：
const code = await getCodeFromUser()

// 现在验证验证码：
const userCodeConfig = await getVerificationFromDatabase({
	target: user.email,
})
const isValid = await verifyTOTP({ otp: code, ...userCodeConfig })

if (isValid) {
	await deleteVerificationFromDatabase({ target: user.email })
	// 允许用户继续操作
} else {
	// 显示错误信息
}
```

## 可自定义字符集以增强安全性

### 为什么字符集很重要

在安全性方面，每一比特的熵都很重要。熵衡量的是不可预测性，进而衡量 OTP 的安全性。传统的 TOTP 设置通常使用 6 位数字验证码，提供一百万（10^6）种组合。这是此实现的默认行为。虽然这已经很强大，但仍有改进空间。

通过引入可自定义的字符集功能，您可以指数级地增加 OTP 的熵，使其对暴力破解攻击更加安全。例如，如果您将字符集扩展为包含 26 个大写字母和 10 个数字，则 6 个字符的 OTP 将有 36^6 = 21 亿种组合。当与速率限制机制配合使用时，此配置实际上可以抵御暴力破解攻击。

### 作为主要认证方式的可能性

有了这种增加的复杂性，TOTP 理论上可以作为主要的认证方式，而不仅仅是第二因素。这对于需要更高安全性的应用特别有用。

### 使用自定义字符集

除了现有选项外，您还可以在 `generateTOTP` 和 `verifyTOTP` 中指定 `charSet`。

以下是如何使用自定义字符集生成 OTP：

```js
import { generateTOTP, verifyTOTP } from '@epic-web/totp'

const { otp, secret, period, digits, algorithm, charSet } = await generateTOTP({
	charSet: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', // 自定义字符集
})

// 请记得将 charSet 也保存到数据库中。

// 验证
const isValid = await verifyTOTP({
	otp,
	secret,
	period,
	digits,
	algorithm,
	charSet,
})
```

顺便提一下，您可能希望排除字母 O 和数字 0，以方便用户输入验证码。

## API

本库使用 `jsdoc` 构建，因此希望您的编辑器支持并能显示所有信息，但以防万一，以下是详细说明：

### `generateTOTP`

```js
/**
 * 创建基于时间的一次性密码 (TOTP)。此方法会创建一个随机密钥
 * （base32 编码），并为当前时间生成 TOTP。作为便利功能，
 * 它还会返回用于生成 TOTP 的配置选项。
 *
 * @param {Object} [options] TOTP 的配置选项。
 * @param {number} [options.period=30] OTP 的有效秒数。默认为 30。
 * @param {number} [options.digits=6] OTP 的长度。默认为 6。
 * @param {string} [options.algorithm='SHA-1'] 使用的算法。默认为 SHA-1。
 * @param {string} [options.secret] 用于 TOTP 的密钥。应为 base32 编码
 * （可使用 https://npm.im/thirty-two）。默认为随机密钥：
 * base32.encode(crypto.randomBytes(10)).toString()。
 * @param {string} [options.charSet='0123456789'] - 使用的字符集，默认为数字 0-9。
 * @returns {Promise<{otp: string, secret: string, period: number, digits: number, algorithm: string, charSet: string}>}
 * OTP、密钥以及用于生成 OTP 的配置选项。
 */
```

### `verifyTOTP`

```js
/**
 * 验证基于时间的一次性密码 (TOTP)。此方法会解码密钥
 * （base32 编码），并验证当前时间的 OTP。
 *
 * @param {Object} options OTP、密钥和 TOTP 的配置选项。
 * @param {string} options.otp 要验证的 OTP。
 * @param {string} options.secret 用于 TOTP 的密钥。
 * @param {number} [options.period] OTP 的有效秒数。
 * @param {number} [options.digits] OTP 的长度。
 * @param {string} [options.algorithm] 使用的算法。
 * @param {string} [options.charSet] 使用的字符集，默认为数字 0-9。
 * @param {number} [options.window] 在当前 OTP 前后检查的 OTP 数量。
 * 默认为 1。
 *
 * @returns {Promise<{delta: number}|null>} 包含 "delta" 的对象，
 * 表示当前 OTP 与已验证 OTP 之间的差值，如果 OTP 无效则返回 null。
 */
```

### `getTOTPAuthUri`

```js
/**
 * 生成 otpauth:// URI，可用于生成二维码或用户手动输入到密码管理器。
 *
 * @param {Object} options TOTP 认证 URI 的配置选项。
 * @param {number} options.period OTP 的有效秒数。
 * @param {number} options.digits OTP 的长度。
 * @param {string} options.algorithm 使用的算法。
 * @param {string} options.secret 用于 TOTP 认证 URI 的密钥。
 * @param {string} options.accountName 唯一标识此认证 URI 的方式
 * （以防用户有多个此类 URI）。
 * @param {string} options.issuer 用于 TOTP 认证 URI 的发行者。
 *
 * @returns {string} OTP 认证 URI
 */
```

## 许可证

MIT

<!-- prettier-ignore-start -->
[build-badge]: https://img.shields.io/github/actions/workflow/status/epicweb-dev/totp/release.yml?branch=main&logo=github&style=flat-square
[build]: https://github.com/epicweb-dev/totp/actions?query=workflow%3Arelease
[license-badge]: https://img.shields.io/badge/license-MIT%20License-blue.svg?style=flat-square
[license]: https://github.com/epicweb-dev/totp/blob/main/LICENSE
[coc-badge]: https://img.shields.io/badge/code%20of-conduct-ff69b4.svg?style=flat-square
[coc]: https://kentcdodds.com/conduct
<!-- prettier-ignore-end -->
