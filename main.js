var TenderKeys =require('tendermintelectronkey')
var ETHwallet = require('./ETHv3wallet.js');
var fs = require('graceful-fs')

var tenderKeys = new TenderKeys();

// var mnemonic = tenderKeys.generateRandomMnemonic();
var seed     =  tenderKeys.generateSeed('pppppppppppppppppppppppppppppp');
var keyPair  = tenderKeys.generateKeyPair(seed);

var wallet =new ETHwallet(keyPair.privateKey);
console.log('privateKey')
console.log(keyPair.privateKey.toString('hex'))
console.log('privateKey')
var walletjson = wallet.toV3('123456')



var path= __dirname+'/v3file.json'
console.log(path)
var result = fs.writeFileSync(path,JSON.stringify(walletjson))    
console.log(result)


console.log(walletjson)