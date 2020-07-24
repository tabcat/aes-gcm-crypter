
'use strict'

exports.validKey = (cryptoKey) =>
  cryptoKey &&
  cryptoKey.type === 'secret' &&
  cryptoKey.algorithm &&
  cryptoKey.algorithm.name === 'AES-GCM' &&
  cryptoKey.usages.includes('encrypt') &&
  cryptoKey.usages.includes('decrypt')
