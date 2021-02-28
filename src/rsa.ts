import crypto from 'crypto'

import { pipe } from 'fp-ts/function'
import { map, toError, tryCatch } from 'fp-ts/Either'

import { 
  RSAPublicKey as PublicKey, 
  RSAPrivateKey as PrivateKey
} from './types'

export { PublicKey, PrivateKey }
export const MODULOUS = 2048
export const KEY_SIZE = MODULOUS / 8

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
      public_key: keys.publicKey as PublicKey,
      private_key: keys.privateKey as PrivateKey
    }))
  )

export const encrypt = (
  public_key: PublicKey,
  secret?: string
) => (
  data: string | Buffer,
  encoding: BufferEncoding = 'utf-8'
) => crypto.publicEncrypt(
  {
    key: public_key,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: "sha256",
    passphrase: secret || undefined
  },
  Buffer.isBuffer(data) ? data : Buffer.from(data, encoding)
)

export const decrypt = (
  private_key: PrivateKey,
  secret?: string
) => (
  data: string | Buffer,
  encoding: BufferEncoding = 'base64'
) => crypto.privateDecrypt(
  {
    key: private_key,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: "sha256",
    passphrase: secret || undefined
  },
  Buffer.isBuffer(data) ? data : Buffer.from(data, encoding)
)
