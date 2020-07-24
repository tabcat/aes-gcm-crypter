
'use strict'
const webcrypto = require('@tabcat/webcrypto-ponyfill')
const expectDefined = (param) => new Error(`expected ${param} to be defined`)
const invalidCryptoKey = () => new Error('invalid CryptoKey given')
const invalidIVLen = () => new Error('iv was invalid length')

class Crypter {
  constructor (cryptoKey) {
    if (!cryptoKey) throw expectDefined('cryptoKey')
    if (
      cryptoKey.type !== 'secret' ||
      cryptoKey.name !== 'AES-GCM' ||
      !cryptoKey.usages.includes('encrypt') ||
      !cryptoKey.usages.includes('decrypt')
    ) throw invalidCryptoKey()
    this._cryptoKey = cryptoKey
  }

  /**
  * Creates an instance of Crypter.
  * @param {CryptoKey} cryptoKey The key to use for the crypter.
  * @return {Crypter}
  */
  static create (cryptoKey) {
    return new Crypter(cryptoKey)
  }

  /**
  * Generates a random aes-gcm key.
  * @param {ArrayBuffer} rawKey The raw aes key. Output from exportKey.
  * @return {CryptoKey}
  */
  static async generateKey (length = 128) {
    return webcrypto.get().subtle.generateKey(
      {
        name: 'AES-GCM',
        length: length // can be  128, 192, or 256
      },
      true, // exportable
      ['encrypt', 'decrypt']
    )
  }

  /**
  * Imports a raw aes-gcm key.
  * @param {ArrayBuffer} rawKey The raw aes key as an ArrayBuffer. Output from exportKey.
  * @return {CryptoKey} The imported key.
  */
  static async importKey (rawKey) {
    if (!rawKey) throw expectDefined('rawKey')
    return webcrypto.get().subtle.importKey(
      'raw',
      rawKey,
      { name: 'AES-GCM' },
      true, // exportable
      ['encrypt', 'decrypt']
    )
  }

  /**
  * Exports an aes-gcm CryptoKey.
  * @param {CryptoKey} cryptoKey The key to export. Output from generateKey or importKey.
  * @return {ArrayBuffer} The raw aes key.
  */
  static async exportKey (cryptoKey) {
    if (!cryptoKey) throw expectDefined('cryptoKey')
    return webcrypto.get().subtle.exportKey('raw', cryptoKey)
  }

  /**
  * Generates a random initialization vector.
  * @return {Uint8Array} The initialization vector.
  */
  static generateIV () {
    return webcrypto.get().getRandomValues(new Uint8Array(12))
  }

  /**
  * Encrypts the bytes using the crypter instance cryptoKey.
  * @param {ArrayBuffer} bytes The bytes to be encrypted.
  * @param {Uint8Array} [iv] The initialization vector to use.
  * @return {object} An object including the encrypted bytes and initialization vector
  */
  async encrypt (bytes, iv = Crypter.generateIV()) {
    if (!bytes) throw expectDefined('bytes')
    if (!iv) throw expectDefined('iv')
    iv = Uint8Array.from(iv)
    if (iv.length !== 12) throw invalidIVLen()
    const cipherbytes = await webcrypto.get().subtle.encrypt(
      { ...this._cryptoKey.algorithm, iv },
      this._cryptoKey,
      bytes
    )
    return { cipherbytes, iv }
  }

  /**
  * Decrypted the ciphered bytes using the crypter instance crytoKey.
  * @param {ArrayBuffer} cipherbytes The encrypted bytes.
  * @param {Uint8Array} iv The initialization vector used to encrypt.
  * @return {object} An object including the encrypted bytes and initialization vector
  */
  async decrypt (cipherbytes, iv) {
    if (!cipherbytes) throw expectDefined('cipherbytes')
    if (!iv) throw expectDefined('iv')
    iv = Uint8Array.from(iv)
    if (iv.length !== 12) throw invalidIVLen()
    return webcrypto.get().subtle.decrypt(
      { ...this._cryptoKey.algorithm, iv },
      this._cryptoKey,
      cipherbytes
    )
  }
}

module.exports = Crypter
