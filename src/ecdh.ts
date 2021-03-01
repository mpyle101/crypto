import crypto from 'crypto'
import { Newtype, iso } from 'newtype-ts'

export interface Secret extends
  Newtype<{ readonly Secret: unique symbol }, Buffer> {}

interface PublicKey extends
  Newtype<{ readonly PublicKey: unique symbol }, Buffer> {}

interface PrivateKey extends
  Newtype<{ readonly PrivateKey: unique symbol }, Buffer> {}

const isoSecret     = iso<Secret>()
const isoPublicKey  = iso<PublicKey>()
const isoPrivateKey = iso<PrivateKey>()

export const generate_keys = () => {
  const ecdh = crypto.createECDH('secp521r1')
  ecdh.generateKeys()

  return {
    public_key: isoPublicKey.wrap(ecdh.getPublicKey()),
    private_key: isoPrivateKey.wrap(ecdh.getPrivateKey())
  }
}

export const compute_secret = (
  public_key: PublicKey,
  private_key: PrivateKey
) => {
  const ecdh = crypto.createECDH('secp521r1')
  ecdh.setPrivateKey(isoPrivateKey.unwrap(private_key))
  return isoSecret.wrap(ecdh.computeSecret(isoPublicKey.unwrap(public_key)))
}