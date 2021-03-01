import crypto from 'crypto'

const public_header = '-----BEGIN PUBLIC KEY-----'
const public_footer = '-----END PUBLIC KEY-----'
const private_header = '-----BEGIN PRIVATE KEY-----'
const private_footer = '-----END PRIVATE KEY-----'

const LINE_LENGTH = 64

const to_pem = (key, header, footer) => {
  const count  = Math.ceil(key.length / LINE_LENGTH)
  const chunks = [...Array(count).keys()].reduce((acc, idx) => {
    acc.push(key.substr(idx * LINE_LENGTH, LINE_LENGTH)) 
    return acc
  }, [] as string[])
  const body = chunks.join('\n')
  return `${header}\n${body}\n${footer}\n`
}

const from_pem = (pem: string) =>
  pem.split('\n').slice(1, -2).join('')

const s_ecdh = crypto.createECDH('secp521r1')
s_ecdh.generateKeys()
const s_public_key  = s_ecdh.getPublicKey('base64')
const s_private_key = s_ecdh.getPrivateKey('base64')

const c_ecdh = crypto.createECDH('secp521r1')
c_ecdh.generateKeys()
const c_public_key  = c_ecdh.getPublicKey('base64')
const c_private_key = c_ecdh.getPrivateKey('base64')

const ecdh1 = crypto.createECDH('secp521r1')
ecdh1.setPrivateKey(s_private_key, 'base64')

const secret1 = ecdh1.computeSecret(c_public_key, 'base64')

const s_public_pem  = to_pem(s_public_key, public_header, public_footer)
const s_private_pem = to_pem(s_private_key, private_header, private_footer)

const private_key = from_pem(s_private_pem)
const ecdh2 = crypto.createECDH('secp521r1')
ecdh2.setPrivateKey(private_key, 'base64')
const secret2 = ecdh2.computeSecret(c_public_key, 'base64')

const salt = crypto.randomBytes(32)
const key1 = crypto.pbkdf2Sync(secret1, salt, 400000, 32, 'sha512')
const key2 = crypto.pbkdf2Sync(secret2, salt, 400000, 32, 'sha512')

const aes_encrypt = (v, key, iv) => {
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv)
  const encrypted = cipher.update(v, 'utf-8', 'base64')
  return encrypted + cipher.final('base64')
}

const aes_decrypt = (v, key, iv) => {
  const cipher = crypto.createDecipheriv('aes-256-cbc', key, iv)
  const decrypted = cipher.update(v, 'base64')
  return decrypted + cipher.final('utf-8')
}

const iv = crypto.randomBytes(16)
const text = 'sphinx of black quartz, judge my vow'

const encrypted = aes_encrypt(text, key1, iv)
const decrypted = aes_decrypt(encrypted, key2, iv)
