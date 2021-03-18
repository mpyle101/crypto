import crypto from 'crypto'

import { pipe } from 'fp-ts/function'
import { map, toError, tryCatch } from 'fp-ts/Either'
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
 * Generate a 32 byte AES key from the secret and a random salt.
 * Use the AES key to encrypt the payload.
 * Use the RSA public key to encrypt the AES key.
 * Put the encrypted AES key at the start of the buffer and append
 * the encrypted data.
 */
export const encrypt = (
  public_key: rsa.PublicKey,
  secret: Secret,
  data: string | Buffer,
  encoding: BufferEncoding = 'utf-8'
) => {
  const salt   = crypto.randomBytes(16)
  const aeskey = crypto.pbkdf2Sync(isoSecret.unwrap(secret), salt, 400000, 32, 'sha512')
  const cipher = aes.encrypt(aeskey, data, encoding)

  return pipe(
    rsa.encrypt(public_key)(aeskey),
    map(
      enckey => {
        const result = Buffer.alloc(enckey.length + cipher.length)
        enckey.copy(result)
        cipher.copy(result, enckey.length)
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
  data: string | Buffer,
  encoding: BufferEncoding = 'utf-8'
) => {
  const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data, encoding)

  return pipe(
    buffer.slice(0, rsa.KEY_SIZE),
    rsa.decrypt(private_key),
    map(
      key => {
        const cipher = buffer.slice(rsa.KEY_SIZE)
        return aes.decrypt(key, buffer.slice(rsa.KEY_SIZE), encoding)
      }
    )
  )
}