
'use strict'

const assert = require('assert')
const Crypter = require('../src')
const { validKey } = require('../src/util')

describe('Crypter AES-GCM', function () {
  const arrayKey = [76, 73, 177, 88, 51, 188, 180, 24, 59, 83, 39, 58, 149, 204, 53, 219]
  const arrayIV = [85, 77, 207, 95, 0, 216, 50, 22, 222, 231, 127, 72]
  const arrayBytes = Array.from(Buffer.from('encrypt this please'))
  const arrayCipherbytes = [12, 236, 40, 237, 26, 239, 24, 40, 121, 103, 34, 247, 149, 42, 106, 91, 147, 183, 15, 88, 33, 25, 180, 204, 17, 118, 237, 131, 158, 109, 76, 56, 179, 63, 240]
  let cryptoKey, rawKey

  describe('class', function () {
    it('generate key', async function () {
      cryptoKey = await Crypter.generateKey()
      rawKey = await Crypter.exportKey(cryptoKey)
      assert.strict.equal(validKey(cryptoKey), true)
      assert.strict.equal(cryptoKey.algorithm.length, 128)
    })

    it('import key', async function () {
      cryptoKey = await Crypter.importKey(Uint8Array.from(arrayKey).buffer)
      assert.strict.equal(validKey(cryptoKey), true)
      assert.strict.equal(cryptoKey.algorithm.length, 128)
    })

    it('export key', async function () {
      rawKey = await Crypter.exportKey(cryptoKey)
      assert.strict.equal(validKey(cryptoKey), true)
      assert.strict.equal(cryptoKey.algorithm.length, 128)
      assert.strict.deepEqual(Array.from(new Uint8Array(rawKey)), arrayKey)
    })

    it('generate iv', async function () {
      const iv = Crypter.generateIV()
      assert.strict.equal(iv.length, 12)
    })
  })

  describe('instance', function () {
    let crypter

    before(async function () {
      crypter = await Crypter.create(cryptoKey)
    })

    it('generate iv', async function () {
      const iv = crypter.generateIV()
      assert.strict.equal(iv.length, 12)
    })

    it('encrypt', async function () {
      const { cipherbytes, iv } = await crypter.encrypt(
        Uint8Array.from(arrayBytes).buffer,
        Uint8Array.from(arrayIV)
      )
      assert.strict.equal(cipherbytes.constructor === ArrayBuffer, true)
      assert.strict.equal(iv.constructor === Uint8Array, true)
      assert.strict.equal(iv.length, 12)
      assert.strict.deepEqual(Array.from(new Uint8Array(cipherbytes)), arrayCipherbytes)
    })

    it('decrypt', async function () {
      const bytes = await crypter.decrypt(
        Uint8Array.from(arrayCipherbytes).buffer,
        Uint8Array.from(arrayIV)
      )
      assert.strict.equal(bytes.constructor === ArrayBuffer, true)
      assert.strict.deepEqual(Array.from(new Uint8Array(bytes)), arrayBytes)
    })
  })
})
