import { createHmac } from 'crypto'
import { iso } from 'newtype-ts'

import { Secret } from './ecdh'

const DEFAULT_STEP = 20000
const DEFAULT_WINDOW = 1

const isoSecret = iso<Secret>()

const range = (size: number, start = 0, step = 1) =>
  [...Array(size).keys()].map(i => (i * step) + start)

const truncate = (hmac: Buffer) => {
  const offset = hmac[hmac.length - 1] & 0xf
  return ((hmac[offset] & 0x7f) << 24)
    | ((hmac[offset + 1] & 0xff) << 16)
    | ((hmac[offset + 2] & 0xff) << 8)
    |  (hmac[offset + 3] & 0xff)
}

const from_counter = (counter: number) =>
  range(8).reduce((buf, i) => {
    buf[7 - i] = counter & 0xff
    counter >>= 8
    return buf
  }, Buffer.alloc(8))

export const generate_hotp = (
  secret: string | Buffer | Secret,
  counter: number,
  encoding: BufferEncoding = 'base64'
) => {
  const decoded = Buffer.isBuffer(secret)
    ? secret
    : typeof secret === 'string'
      ? Buffer.from(secret, encoding)
      : isoSecret.get(secret)

  const hmac   = createHmac('sha1', decoded);
  const buffer = from_counter(counter)
  const digest = hmac.update(buffer).digest()
  const code   = truncate(digest)

  return code % (10 ** 6)
}

export const generate_token = (
  secret: string | Buffer | Secret,
  offset = 0,
  step = DEFAULT_STEP,
  encoding: BufferEncoding = 'base64'
) => {
  const counter = Math.round(Date.now() / step)
  return generate_hotp(secret, counter + offset, encoding)
}

export const verify_token = (
  token: number,
  secret: string | Buffer | Secret,
  window = DEFAULT_WINDOW,
  step = DEFAULT_STEP
) => {
  if (Math.abs(window) > 10) {
    throw new Error('TOTP window > 10')
  }
  return range(3, -Math.abs(window)).some(
    offset => generate_token(secret, offset, step) === token
  )
}
