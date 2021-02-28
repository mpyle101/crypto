import crypto from 'crypto'

export const MODULOUS = 2048
export const KEY_SIZE = MODULOUS / 8

export const generate_keys = (secret?: string) => {
  const encoding = {
    type: 'pkcs8',
    format: 'pem'
  }
  if (secret) {
    encoding['cipher'] = 'aes-256-cbc'
    encoding['passphrase'] = secret
  }

  const { 
    publicKey: public_key, 
    privateKey: private_key
  } = crypto.generateKeyPairSync('rsa', {
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
  })

  return { public_key, private_key }
}

export const encrypt = ({
  public_key,
  data,
  secret,
  encoding = 'utf-8'
}:{
  public_key: string
  data: string | Buffer
  secret?: string
  encoding?: BufferEncoding
}) => crypto.publicEncrypt(
  {
    key: public_key,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: "sha256",
    passphrase: secret || undefined
  },
  Buffer.isBuffer(data) ? data : Buffer.from(data, encoding)
)

export const decrypt = ({
  private_key,
  data,
  secret,
  encoding = 'base64'
}: {
  private_key: string
  data: string | Buffer
  secret?: string
  encoding?: BufferEncoding
}) => crypto.privateDecrypt(
  {
    key: private_key,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: "sha256",
    passphrase: secret || undefined
  },
  Buffer.isBuffer(data) ? data : Buffer.from(data, encoding)
)