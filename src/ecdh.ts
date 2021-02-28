import crypto from 'crypto'

import { PublicKey, PrivateKey, Secret } from './ecdh.types'

export { Secret }

export const generate_keys = () => {
  const ecdh = crypto.createECDH('secp521r1')
  ecdh.generateKeys()

  return {
    public_key: ecdh.getPublicKey() as PublicKey,
    private_key: ecdh.getPrivateKey() as PrivateKey
  }
}

export const compute_secret = (
  public_key: PublicKey,
  private_key: PrivateKey
) => {
  const ecdh = crypto.createECDH('secp521r1')
  ecdh.setPrivateKey(private_key)
  return ecdh.computeSecret(public_key) as Secret
}