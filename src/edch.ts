import crypto from 'crypto'

export const generate_keys = () => {
  const ecdh = crypto.createECDH('secp521r1')
  ecdh.generateKeys()

  return {
    public_key: ecdh.getPublicKey(),
    private_key: ecdh.getPrivateKey()
  }
}

export const compute_secret = (
  public_key: Buffer,
  private_key: Buffer
) => {
  const ecdh = crypto.createECDH('secp521r1')
  ecdh.setPrivateKey(private_key)
  return ecdh.computeSecret(public_key)
}