import crypto from 'crypto'

import { pipe } from 'fp-ts/function'
import { getOrElseW, map, toError, tryCatch, right, left } from 'fp-ts/Either'
import { Newtype, iso } from 'newtype-ts'

import * as aes  from './aes'
import * as rsa  from './rsa'

export interface Secret extends
  Newtype<{ readonly Secret: unique symbol }, Buffer> {}

export interface PublicKey extends
  Newtype<{ readonly PublicKey: unique symbol }, crypto.KeyObject> {}

export interface PrivateKey extends
  Newtype<{ readonly PrivateKey: unique symbol }, crypto.KeyObject> {}

const isoSecret = iso<Secret>()
const isoPublicKey = iso<PublicKey>()
const isoPrivateKey = iso<PrivateKey>()

const DIGEST_SIZE = 32

const rethrow = (err: Error) => { throw (err) }

export const generate_keys = () => pipe(
  tryCatch(
    () => crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
    toError
  ),
  map(keys => ({
    public_key: isoPublicKey.wrap(keys.publicKey),
    private_key: isoPrivateKey.wrap(keys.privateKey)
  }))
)

export const compute_secret = (
  public_key: PublicKey,
  private_key: PrivateKey
) => pipe(
  tryCatch(
    () => crypto.diffieHellman({
            publicKey: isoPublicKey.unwrap(public_key),
            privateKey: isoPrivateKey.unwrap(private_key)
          }),
    toError
  ),
  map(isoSecret.wrap)
)

/**
 * Generate an HMAC of the data using the secret key
 * Generate a random 32 byte AES key and a random salt.
 * Use the AES key to encrypt the payload.
 * Use the RSA public key to encrypt the AES key.
 * 
 * Create the payload from the digest, then the RSA encrypted
 * AES key, then the AES encrypted data.
 */
export const encrypt = (
  public_key: rsa.PublicKey,
  secret: Secret,
  data: string | Buffer,
  encoding: BufferEncoding = 'utf-8'
) => {
  const hmac   = crypto.createHmac('sha256', isoSecret.unwrap(secret))
  const digest = hmac.update(data).digest()

  const salt   = crypto.randomBytes(16)
  const aeskey = crypto.pbkdf2Sync(crypto.randomBytes(32), salt, 400000, 32, 'sha512')
  const cipher = aes.encrypt(aeskey, data, encoding)

  return pipe(
    rsa.encrypt(public_key)(aeskey),
    map(
      enckey => {
        const result = Buffer.alloc(digest.length + enckey.length + cipher.length)
        digest.copy(result)
        enckey.copy(result, digest.length)
        cipher.copy(result, digest.length + enckey.length)
        return result
      }
    )
  )
}

/**
 * Get the encrypted AES key from the begining of the data.
 * Decrypt the AES key with the RSA private key.
 * Decrypt the rest of the data using the AES key.
 */
export const decrypt = (
  private_key: rsa.PrivateKey,
  secret: Secret,
  cipher: string | Buffer,
  encoding: BufferEncoding = 'utf-8'
) => {
  const buffer = Buffer.isBuffer(cipher) ? cipher : Buffer.from(cipher, encoding)
  const digest = buffer.slice(0, DIGEST_SIZE)
  const aeskey = pipe(
    buffer.slice(DIGEST_SIZE, DIGEST_SIZE + rsa.KEY_SIZE),
    rsa.decrypt(private_key),
    getOrElseW(rethrow)
  )
  const data = aes.decrypt(aeskey, buffer.slice(DIGEST_SIZE + rsa.KEY_SIZE))
  const hmac = crypto.createHmac('sha256', isoSecret.unwrap(secret))
  const hash = hmac.update(data).digest()
  return pipe(
    digest.compare(hash),
    res => res === 0 ? right(data) : left(new Error('HMAC mismatch'))
  )
}