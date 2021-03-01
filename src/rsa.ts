import crypto from 'crypto'

import { pipe } from 'fp-ts/function'
import { map, toError, tryCatch } from 'fp-ts/Either'
import { Newtype, iso } from 'newtype-ts'

export const MODULOUS = 2048
export const KEY_SIZE = MODULOUS / 8

export interface PublicKey extends
  Newtype<{ readonly RSAPublicKey: unique symbol }, string> {}

export interface PrivateKey extends
  Newtype<{ readonly RSAPrivateKey: unique symbol }, string> {}

const isoPublicKey  = iso<PublicKey>()
const isoPrivateKey = iso<PrivateKey>()

export const generate_keys = (secret?: string) =>
  pipe(
    tryCatch(
      () => crypto.generateKeyPairSync('rsa', {
              modulusLength: MODULOUS,
              publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
              },
              privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem',
                cipher: secret ? 'aes-256-cbc' : undefined,
                passphrase: secret || undefined
              },
            }),
      toError
    ),
    map(keys => ({
      public_key: isoPublicKey.from(keys.publicKey),
      private_key: isoPrivateKey.from(keys.privateKey)
    }))
  )

export const encrypt = (
  public_key: PublicKey,
  secret?: string
) => (
  data: string | Buffer,
  encoding: BufferEncoding = 'utf-8'
) => tryCatch(
  () => crypto.publicEncrypt(
    {
      key: isoPublicKey.get(public_key),
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
      passphrase: secret || undefined
    },
    Buffer.isBuffer(data) ? data : Buffer.from(data, encoding)
  ),
  toError
)

export const decrypt = (
  private_key: PrivateKey,
  secret?: string
) => (
  data: string | Buffer,
  encoding: BufferEncoding = 'base64'
) => tryCatch(
  () => crypto.privateDecrypt(
    {
      key: isoPrivateKey.get(private_key),
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: "sha256",
      passphrase: secret || undefined
    },
    Buffer.isBuffer(data) ? data : Buffer.from(data, encoding)
  ),
  toError
)
