import crypto from 'crypto'

import { pipe, flow } from 'fp-ts/function'
import { bind, bindTo, fold, getOrElseW, map, right } from 'fp-ts/Either'

import { aes, dh, rsa, totp } from './index'

const PUBLIC_HEADER  = '-----BEGIN PUBLIC KEY-----'
const PUBLIC_FOOTER  = '-----END PUBLIC KEY-----'
const PRIVATE_HEADER = '-----BEGIN PRIVATE KEY-----'
const PRIVATE_FOOTER = '-----END PRIVATE KEY-----'
const PRIVATE_ENC_HEADER = '-----BEGIN ENCRYPTED PRIVATE KEY-----'
const PRIVATE_ENC_FOOTER = '-----END ENCRYPTED PRIVATE KEY-----'

const PLAIN_TEXT = 'sphinx of black quartz, judge my vow'

export const rethrow = (err: Error) => { throw (err) }

describe('Crypto tests', () => {
  describe('AES', () => {
    it('Should encrypt / decrypt simple text', () => {
      const secret = crypto.randomBytes(32)

      const cipher = aes.encrypt(secret, PLAIN_TEXT)
      expect(cipher.toString('utf-8')).not.toEqual(PLAIN_TEXT)

      const plain = aes.decrypt(secret, cipher)
      expect(plain.toString('utf-8')).toEqual(PLAIN_TEXT)
    })

    it('Should encrypt / decrypt random bytes', () => {
      const data   = crypto.randomBytes(102)
      const secret = crypto.randomBytes(32)

      const cipher = aes.encrypt(secret, data)
      expect(cipher).not.toEqual(data)

      const plain = aes.decrypt(secret, cipher)
      expect(plain).toEqual(data)
    })

    it('Should encrypt / decrypt larger data', () => {
      const data   = crypto.randomBytes(12345)
      const secret = crypto.randomBytes(32)

      const cipher = aes.encrypt(secret, data)
      expect(cipher).not.toEqual(data)

      const plain = aes.decrypt(secret, cipher)
      expect(plain).toEqual(data)
    })
  })

  describe('RSA', () => {
    it('Should generate a simple key pair', () =>
      pipe(
        undefined,
        rsa.generate_keys,
        fold(
          rethrow,
          ({ public_key, private_key }) => {
            expect(public_key).toContain(PUBLIC_HEADER)
            expect(public_key).toContain(PUBLIC_FOOTER)
            expect(private_key).toContain(PRIVATE_HEADER)
            expect(private_key).toContain(PRIVATE_FOOTER)
          }
        )
      )
    )

    it('Should generate an encrypted key pair', () =>
      pipe(
        'my little pony',
        rsa.generate_keys,
        fold(
          rethrow,
          ({ public_key, private_key }) => {
            expect(public_key).toContain(PUBLIC_HEADER)
            expect(public_key).toContain(PUBLIC_FOOTER)
            expect(private_key).toContain(PRIVATE_ENC_HEADER)
            expect(private_key).toContain(PRIVATE_ENC_FOOTER)
          }
        )
      )
    )

    it('Should encrypt / decrypt simple text', () =>
      pipe(
        bindTo('data')(right(PLAIN_TEXT)),
        bind('keys',   () => rsa.generate_keys()),
        bind('cipher', ({ keys, data })   => rsa.encrypt(keys.public_key)(data)),
        bind('plain',  ({ keys, cipher }) => rsa.decrypt(keys.private_key)(cipher)),
        fold(
          rethrow,
          ({ cipher, plain }) => {
            expect(cipher.toString('utf-8')).not.toEqual(PLAIN_TEXT)
            expect(plain.toString('utf-8')).toEqual(PLAIN_TEXT)
          }
        )
      )
    )

    it('Should encrypt / decrypt random bytes', () =>
      pipe(
        bindTo('data')(right(crypto.randomBytes(102))),
        bind('keys',   () => rsa.generate_keys()),
        bind('cipher', ({ keys, data })   => rsa.encrypt(keys.public_key)(data)),
        bind('plain',  ({ keys, cipher }) => rsa.decrypt(keys.private_key)(cipher)),
        fold(
          rethrow,
          ({ cipher, plain, data }) => {
            expect(cipher).not.toEqual(data)
            expect(plain).toEqual(data)
          }
        )
      )
    )

    it('Should encrypt / decrypt with encrypted keys', () =>
      pipe(
        bindTo('data')(right(crypto.randomBytes(102))),
        bind('secret', () => right('my little pony')),
        bind('keys',   () => rsa.generate_keys()),
        bind('cipher', ({ keys, secret, data }) =>
          rsa.encrypt(keys.public_key, secret)(data)),
        bind('plain', ({ keys, secret, cipher }) =>
          rsa.decrypt(keys.private_key, secret)(cipher)),
        fold(
          rethrow,
          ({ cipher, plain, data }) => {
            expect(cipher).not.toEqual(data)
            expect(plain).toEqual(data)
          }
        )
      )
    )
  })

  describe('TOTP', () => {
    const secret = pipe(
      bindTo('s_keys')(dh.generate_keys()),
      bind('c_keys', dh.generate_keys),
      fold(
        rethrow,
        ({ s_keys: { public_key }, c_keys: { private_key } }) => 
          dh.compute_secret(public_key, private_key)
      ),
      getOrElseW(rethrow)
    )

    it('Should generate the same HOTP token for the same counter', () => {
      const s_token = totp.generate_hotp(secret, 3)
      const c_token = totp.generate_hotp(secret, 3)

      expect(s_token).toEqual(c_token)
    })

    it('Should generate the different HOTP tokens for different counters', () => {
      const s_token = totp.generate_hotp(secret, 3)
      const c_token = totp.generate_hotp(secret, 4)

      expect(s_token).not.toEqual(c_token)
    })

    it('Should verify a TOTP token', () => {
      const token = totp.generate_token(secret)
      expect(totp.verify_token(token, secret)).toBeTruthy()
    })

    it('Should verify a TOTP token 15 seconds in the past', () => {
      const token = totp.generate_token(secret)

      const now  = Date.now()
      const mock = jest.spyOn(global.Date, 'now')
        .mockReturnValue(now - 15000)

      expect(totp.verify_token(token, secret)).toBeTruthy()
      mock.mockRestore()
    })

    it('Should verify a TOTP token 15 seconds in the future', () => {
      const token = totp.generate_token(secret)

      const now  = Date.now()
      const mock = jest.spyOn(global.Date, 'now')
        .mockReturnValue(now + 15000)

      expect(totp.verify_token(token, secret)).toBeTruthy()
      mock.mockRestore()
    })

    it('Should NOT verify a TOTP token 50 seconds in the past', () => {
      const token = totp.generate_token(secret)

      const now  = Date.now()
      const mock = jest.spyOn(global.Date, 'now')
        .mockReturnValue(now - 50000)

      expect(totp.verify_token(token, secret)).toBeFalsy()
      mock.mockRestore()
    })

    it('Should NOT verify a TOTP token 50 seconds in the future', () => {
      const token = totp.generate_token(secret)

      const now  = Date.now()
      const mock = jest.spyOn(global.Date, 'now')
        .mockReturnValue(now + 50000)

      expect(totp.verify_token(token, secret)).toBeFalsy()
      mock.mockRestore()
    })
  })

  describe('DH', () => {
    const { public_key, private_key } = pipe(
      undefined,
      rsa.generate_keys,
      getOrElseW(rethrow)
    )
    const secret = pipe(
      bindTo('s_keys')(dh.generate_keys()),
      bind('c_keys', dh.generate_keys),
      fold(
        rethrow,
        ({ s_keys: { public_key }, c_keys: { private_key } }) =>
          dh.compute_secret(public_key, private_key)
      ),
      getOrElseW(rethrow)
    )

    it('Should generate a key pair', () =>
      flow(
        dh.generate_keys,
        fold(
          rethrow,
          keys => {
            expect(keys.public_key).toBeDefined()
            expect(keys.private_key).toBeDefined()
          }
        )
      )()
    )

    it('Should compute a shared secret', () =>
      pipe(
        bindTo('s_keys')(dh.generate_keys()),
        bind('c_keys', dh.generate_keys),
        bind('c_secret', ({ s_keys, c_keys }) =>
          dh.compute_secret(s_keys.public_key, c_keys.private_key)),
        bind('s_secret', ({ s_keys, c_keys }) =>
          dh.compute_secret(c_keys.public_key, s_keys.private_key)),
        fold(
          rethrow,
          ({ s_secret, c_secret }) => expect(s_secret).toEqual(c_secret)
        )
      )
    )

    it('Should encrypt / decrypt simple text', () =>
      pipe(
        bindTo('data')(right(PLAIN_TEXT)),
        bind('cipher', ({ data }) => dh.encrypt(public_key, secret, data)),
        bind('plain', ({ data, cipher }) => dh.decrypt(private_key, secret, cipher)),
        fold(
          rethrow,
          ({ cipher, plain, data }) => {
            expect(cipher.toString('utf-8')).not.toEqual(data)
            expect(plain.toString('utf-8')).toEqual(data)
          }
        )
      )
    )

    it('Should encrypt / decrypt random bytes', () => {
      const { cipher, plain, data } = pipe(
        bindTo('data')(right(crypto.randomBytes(102))),
        bind('cipher', ({ data }) => dh.encrypt(public_key, secret, data)),
        bind('plain', ({ data, cipher }) => dh.decrypt(private_key, secret, cipher)),
        getOrElseW(rethrow)
      )

      expect(cipher).not.toEqual(data)
      expect(plain).toEqual(data)
    })

    it('Should encrypt / decrypt larger data', () => {
      const { cipher, plain, data } = pipe(
        bindTo('data')(right(crypto.randomBytes(12345))),
        bind('cipher', ({ data }) => dh.encrypt(public_key, secret, data)),
        bind('plain', ({ data, cipher }) => dh.decrypt(private_key, secret, cipher)),
        getOrElseW(rethrow)
      )

      expect(cipher).not.toEqual(data)
      expect(plain).toEqual(data)
    })
  })
})
