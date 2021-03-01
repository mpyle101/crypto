import crypto from 'crypto'

import { pipe } from 'fp-ts/function'
import { map } from 'fp-ts/Either'
import { iso } from 'newtype-ts'

import * as aes  from './aes'
import * as ecdh from './ecdh'
import * as rsa  from './rsa'
import { Secret } from './ecdh'

const get = iso<Secret>().get

export const encrypt = (
  public_key: rsa.PublicKey,
  secret: ecdh.Secret,
  data: string | Buffer,
  encoding: BufferEncoding = 'utf-8'
) => {
  const salt   = crypto.randomBytes(16)
  const aeskey = crypto.pbkdf2Sync(get(secret), salt, 400000, 32, 'sha512')
  const cipher = aes.encrypt(aeskey, data, encoding)

  return pipe(
    rsa.encrypt(public_key)(salt),
    map(
      encslt => {
        const result = Buffer.alloc(encslt.length + cipher.length)
        encslt.copy(result)
        cipher.copy(result, encslt.length)
        return result
      }
    )
  )
}

export const decrypt = (
  private_key: rsa.PrivateKey,
  secret: ecdh.Secret,
  data: string | Buffer,
  encoding: BufferEncoding = 'utf-8'
) => {
  const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data, encoding)
  const encslt = buffer.slice(0, rsa.KEY_SIZE)

  return pipe(
    rsa.decrypt(private_key)(encslt),
    map(
      salt => {
        const aeskey = crypto.pbkdf2Sync(get(secret), salt, 400000, 32, 'sha512')
        const cipher = buffer.slice(rsa.KEY_SIZE)
        return aes.decrypt(aeskey, buffer.slice(rsa.KEY_SIZE), encoding)
      }
    )
  )
}