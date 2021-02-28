import { brand, string as string_t, Branded, TypeOf } from 'io-ts'

export type PublicKey  = TypeOf<typeof PublicKey>
export type PrivateKey = TypeOf<typeof PrivateKey>

interface RSAPublicKey {
  readonly PublicKey: unique symbol
}

const PublicKey = brand(
  string_t,
  (s): s is Branded<string, RSAPublicKey> => true,
  'PublicKey'
)

interface RSAPrivateKey {
  readonly PrivateKey: unique symbol
}

const PrivateKey = brand(
  string_t,
  (s): s is Branded<string, RSAPrivateKey> => true,
  'PrivateKey'
)

