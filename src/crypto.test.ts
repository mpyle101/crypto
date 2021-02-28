import crypto from 'crypto'

import { aes, dh, ecdh, rsa } from './index'

const PUBLIC_HEADER  = '-----BEGIN PUBLIC KEY-----'
const PUBLIC_FOOTER  = '-----END PUBLIC KEY-----'
const PRIVATE_HEADER = '-----BEGIN PRIVATE KEY-----'
const PRIVATE_FOOTER = '-----END PRIVATE KEY-----'
const PRIVATE_ENC_HEADER = '-----BEGIN ENCRYPTED PRIVATE KEY-----'
const PRIVATE_ENC_FOOTER = '-----END ENCRYPTED PRIVATE KEY-----'

const PLAIN_TEXT = 'sphinx of black quartz, judge my vow'

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
    it('Should generate a simple key pair', () => {
      const { public_key, private_key } = rsa.generate_keys()

      expect(public_key).toContain(PUBLIC_HEADER)
      expect(public_key).toContain(PUBLIC_FOOTER)
      expect(private_key).toContain(PRIVATE_HEADER)
      expect(private_key).toContain(PRIVATE_FOOTER)
    })

    it('Should generate an encrypted key pair', () => {
      const secret = 'my little pony'
      const { public_key, private_key } = rsa.generate_keys(secret)

      expect(public_key).toContain(PUBLIC_HEADER)
      expect(public_key).toContain(PUBLIC_FOOTER)
      expect(private_key).toContain(PRIVATE_ENC_HEADER)
      expect(private_key).toContain(PRIVATE_ENC_FOOTER)
    })

    it('Should encrypt / decrypt simple text', () => {
      const { public_key, private_key } = rsa.generate_keys()

      const cipher = rsa.encrypt({ public_key, data: PLAIN_TEXT })
      expect(cipher.toString('utf-8')).not.toEqual(PLAIN_TEXT)

      const plain = rsa.decrypt({ private_key, data: cipher })
      expect(plain.toString('utf-8')).toEqual(PLAIN_TEXT)
    })

    it('Should encrypt / decrypt random bytes', () => {
      const data = crypto.randomBytes(102)
      const { public_key, private_key } = rsa.generate_keys()

      const cipher = rsa.encrypt({ public_key, data })
      expect(cipher).not.toEqual(data)

      const plain = rsa.decrypt({ private_key, data: cipher })
      expect(plain).toEqual(data)
    })

    it('Should encrypt / decrypt with encrypted keys', () => {
      const secret = 'my little pony'
      const { public_key, private_key } = rsa.generate_keys(secret)

      const cipher = rsa.encrypt({ public_key, secret, data: PLAIN_TEXT })
      expect(cipher.toString('utf-8')).not.toEqual(PLAIN_TEXT)

      const plain = rsa.decrypt({ private_key, secret, data: cipher })
      expect(plain.toString('utf-8')).toEqual(PLAIN_TEXT)
    })
  })

  describe('ECDH', () => {
    it('Should generate a key pair', () => {
      const { public_key, private_key } = ecdh.generate_keys()

      expect(public_key).toBeDefined()
      expect(private_key).toBeDefined()
    })

    it('Should compute a shared secret', () => {
      const {
        public_key: s_public_key,
        private_key: s_private_key
      } = ecdh.generate_keys()
      const {
        public_key: c_public_key,
        private_key: c_private_key
      } = ecdh.generate_keys()

      const c_secret = ecdh.compute_secret(s_public_key, c_private_key)
      const s_secret = ecdh.compute_secret(c_public_key, s_private_key)

      expect(s_secret).toEqual(c_secret)
    })
  })

  describe('DH', () => {
    const { public_key, private_key } = rsa.generate_keys()
    const { public_key: s_public_key } = ecdh.generate_keys()
    const { private_key: c_private_key } = ecdh.generate_keys()
    const secret = ecdh.compute_secret(s_public_key, c_private_key)

    it('Should encrypt / decrypt simple text', () => {
      const cipher = dh.encrypt(public_key, secret, PLAIN_TEXT)
      expect(cipher.toString('utf-8')).not.toEqual(PLAIN_TEXT)

      const plain = dh.decrypt(private_key, secret, cipher)
      expect(plain.toString('utf-8')).toEqual(PLAIN_TEXT)
    })

    it('Should encrypt / decrypt random bytes', () => {
      const data   = crypto.randomBytes(102)
      const secret = crypto.randomBytes(32)

      const cipher = dh.encrypt(public_key, secret, data)
      expect(cipher).not.toEqual(data)

      const plain = dh.decrypt(private_key, secret, cipher)
      expect(plain).toEqual(data)
    })

    it('Should encrypt / decrypt larger data', () => {
      const data   = crypto.randomBytes(12345)
      const secret = crypto.randomBytes(32)

      const cipher = dh.encrypt(public_key, secret, data)
      expect(cipher).not.toEqual(data)

      const plain = dh.decrypt(private_key, secret, cipher)
      expect(plain).toEqual(data)
    })
  })
})
