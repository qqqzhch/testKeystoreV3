var TenderKeys =require('tendermintelectronkey')
var ETHwallet = require('./ETHv3wallet.js');
var fs = require('graceful-fs')

var tenderKeys = new TenderKeys();

// var mnemonic = tenderKeys.generateRandomMnemonic();






var path= __dirname+'/v3file.json'
console.log(path)
var v3file =fs.readFileSync(path,'utf-8');
console.log(v3file);
var wallet = ETHwallet.fromV3(v3file,'123456');
console.log('privKey')
console.log(wallet._privKey.toString('hex'))
console.log('privKey')

