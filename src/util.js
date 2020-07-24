
'use strict'

exports.validKey = (cryptoKey) =>
  cryptoKey &&
  cryptoKey.type === 'secret' &&
  cryptoKey.name === 'AES-GCM' &&
  cryptoKey.usages.includes('encrypt') &&
  cryptoKey.usages.includes('decrypt')
