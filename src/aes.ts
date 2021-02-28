import crypto from 'crypto'

const AES_IV_LENGTH  = 12
const AES_TAG_LENGTH = 16

export const encrypt = (
  secret: string | Buffer,
  data: string | Buffer,
  encoding: BufferEncoding = 'utf-8'
) => {
  const iv = crypto.randomBytes(AES_IV_LENGTH)
  const cipher = crypto.createCipheriv('aes-256-gcm', secret, iv)

  const plain = Buffer.isBuffer(data) ? data : Buffer.from(data, encoding)
  const chunk = cipher.update(plain)
  const final = cipher.final()
  const tag   = cipher.getAuthTag()

  const size = iv.length + chunk.length + final.length + tag.length
  const encrypted = Buffer.allocUnsafe(size)
  let offset = iv.copy(encrypted)
  offset += chunk.copy(encrypted, offset)
  offset += final.copy(encrypted, offset)
  tag.copy(encrypted, offset)

  return encrypted
}

export const decrypt = (
  secret: string | Buffer,
  data: string | Buffer,
  encoding: BufferEncoding = 'base64'
) => {
  const encrypted = Buffer.isBuffer(data) 
    ? data : Buffer.from(data, encoding)

  const iv  = encrypted.slice(0, AES_IV_LENGTH)
  const tag = encrypted.slice(-AES_TAG_LENGTH)

  const cipher = crypto.createDecipheriv('aes-256-gcm', secret, iv)
  cipher.setAuthTag(tag)
  const chunk = cipher.update(encrypted.slice(iv.length, -AES_TAG_LENGTH))
  const final = cipher.final()

  const plain = Buffer.alloc(chunk.length + final.length)
  chunk.copy(plain)
  final.copy(plain, chunk.length)

  return plain
}