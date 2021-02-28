import { brand, string as string_t, Branded, Type, TypeOf } from 'io-ts'

export type RSAPublicKey   = TypeOf<typeof RSA_PublicKey>
export type RSAPrivateKey  = TypeOf<typeof RSA_PrivateKey>
export type ECDHSecret     = TypeOf<typeof ECDH_Secret>
export type ECDHPublicKey  = TypeOf<typeof ECDH_PublicKey>
export type ECDHPrivateKey = TypeOf<typeof ECDH_PrivateKey>

declare class BufferType extends Type<Buffer> {
  readonly _tag: 'BufferType'
  constructor()
}
interface BufferC extends BufferType { }
declare const buffer: BufferC

interface RSA_PublicKey {
  readonly RSA_PublicKey: unique symbol
}

const RSA_PublicKey = brand(
  string_t,
  (s): s is Branded<string, RSA_PublicKey> => true,
  'RSA_PublicKey'
)

interface RSA_PrivateKey {
  readonly RSA_PrivateKey: unique symbol
}

const RSA_PrivateKey = brand(
  string_t,
  (s): s is Branded<string, RSA_PrivateKey> => true,
  'RSA_PrivateKey'
)

interface ECDH_Secret {
  readonly ECDH_Secret: unique symbol
}
const ECDH_Secret = brand(
  buffer,
  (b): b is Branded<Buffer, ECDH_Secret> => true,
  'ECDH_Secret'
)

interface ECDH_PublicKey {
  readonly ECDH_PublicKey: unique symbol
}
const ECDH_PublicKey = brand(
  buffer,
  (b): b is Branded<Buffer, ECDH_PublicKey> => true,
  'ECDH_PublicKey'
)

interface ECDH_PrivateKey {
  readonly ECDH_PrivateKey: unique symbol
}
const ECDH_PrivateKey = brand(
  buffer,
  (b): b is Branded<Buffer, ECDH_PrivateKey> => true,
  'ECDH_PrivateKey'
)
