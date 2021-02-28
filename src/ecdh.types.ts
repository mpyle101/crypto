import { brand, Type, Branded, TypeOf } from 'io-ts'

export type Secret     = TypeOf<typeof Secret>
export type PublicKey  = TypeOf<typeof PublicKey>
export type PrivateKey = TypeOf<typeof PrivateKey>

declare class BufferType extends Type<Buffer> {
  readonly _tag: 'BufferType'
  constructor()
}
interface BufferC extends BufferType { }
declare const buffer: BufferC

interface ECDHPublicKey {
  readonly PublicKey: unique symbol
}
const PublicKey = brand(
  buffer,
  (b): b is Branded<Buffer, ECDHPublicKey> => true,
  'PublicKey'
)

interface ECDHPrivateKey {
  readonly PrivateKey: unique symbol
}
const PrivateKey = brand(
  buffer,
  (b): b is Branded<Buffer, ECDHPrivateKey> => true,
  'PrivateKey'
)

interface ECDHSecret {
  readonly Secret: unique symbol
}
const Secret = brand(
  buffer,
  (b): b is Branded<Buffer, ECDHSecret> => true,
  'Secret'
)
