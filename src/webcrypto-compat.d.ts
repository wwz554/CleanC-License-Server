export {};

declare global {
  interface SubtleCrypto {
    verify(
      algorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams,
      key: CryptoKey,
      signature: Uint8Array<ArrayBufferLike>,
      data: BufferSource,
    ): Promise<boolean>;
  }
}

