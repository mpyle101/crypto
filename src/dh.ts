import crypto from 'crypto'

import * as aes from './aes'
import * as rsa from './rsa'

export const encrypt = (
  public_key: string,
  secret: string | Buffer,
  data: string | Buffer,
  encoding: BufferEncoding = 'utf-8'
) => {
  const salt   = crypto.randomBytes(16)
  const aeskey = crypto.pbkdf2Sync(secret, salt, 400000, 32, 'sha512')
  const cipher = aes.encrypt(aeskey, data, encoding)
  const encslt = rsa.encrypt({ public_key, data: salt })
  const result = Buffer.alloc(encslt.length + cipher.length)
  encslt.copy(result)
  cipher.copy(result, encslt.length)

  return result
}

export const decrypt = (
  private_key: string,
  secret: string | Buffer,
  data: string | Buffer,
  encoding: BufferEncoding = 'utf-8'
) => {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, encoding)
  const encslt = buf.slice(0, rsa.KEY_SIZE)
  const salt   = rsa.decrypt({ private_key, data: encslt })
  const aeskey = crypto.pbkdf2Sync(secret, salt, 400000, 32, 'sha512')
  const cipher = buf.slice(rsa.KEY_SIZE)

  return aes.decrypt(aeskey, buf.slice(rsa.KEY_SIZE), encoding)
}