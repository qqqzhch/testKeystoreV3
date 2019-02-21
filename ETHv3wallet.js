var randomBytes = require('randombytes');
var crypto = require('crypto');
var Buffer = require('safe-buffer').Buffer;
var scryptsy = require('scrypt.js');
var ethUtil = require('ethereumjs-util');
var uuidv4 = require('uuid/v4');
var TenderKeys =require('tendermintelectronkey');
const bcrypt = require('@webfans/bcrypt');
const saltRounds = 12;

const createKeccakHash = require('keccak');
var nacl = require('tweetnacl')
nacl.util = require('tweetnacl-util')

var tou8 = require('buffer-to-uint8array');
var toBuffer = require('typedarray-to-buffer');


var crypto = require('crypto');

var Amino =require('irisnet-crypto/chains/iris/amino.js')


var encryptSymmetric = function (data, prefix, key) {
  prefix = nacl.util.decodeUTF8(prefix)
  var nonceLength = 24 - prefix.length
  var randomNonce = new Uint8Array(nacl.randomBytes(nacl.secretbox.nonceLength))
  var shortNonce = randomNonce.subarray(0, nonceLength)
  var nonce = new Uint8Array(24)
  nonce.set(prefix)
  nonce.set(shortNonce, prefix.length)
  var box = nacl.secretbox(data, nonce, key)
  var result = new Uint8Array(nonceLength + box.length)
  result.set(shortNonce)
  result.set(box, nonceLength)
  return result
}

var decryptSymmetric = function (data, prefix, key) {
  try {
    prefix = nacl.util.decodeUTF8(prefix)
    var nonceLength = 24 - prefix.length
    var shortNonce = data.subarray(0, nonceLength)
    var nonce = new Uint8Array(24)
    nonce.set(prefix)
    nonce.set(shortNonce, prefix.length)
    var result = nacl.secretbox.open(data.subarray(nonceLength), nonce, key)
  } catch (err) {
    return
  }
  return result
}







var Wallet = function (priv, pub) {
    // 为啥呢？
    if (priv && pub) {
      throw new Error('Cannot supply both a private and a public key to the constructor')
    }
  
    
  
    this._privKey = priv
    this._pubKey = pub
    this.tenderKeys = new TenderKeys();
  }

  function runCipherBuffer (cipher, data) {
    return Buffer.concat([ cipher.update(data), cipher.final() ])
  }


  Object.defineProperty(Wallet.prototype, 'pubKey', {
    get: function () {
      
      if (!this._pubKey) {
        this._pubKey=this.tenderKeys.getPubKeyFromPrivKey(this._privKey.toString('hex'));
      }
      return this._pubKey
    }
  })
  

  Wallet.prototype.getAddress = function () {
      // var  pubKey = ethUtil.toBuffer(p)
        // var dist =createKeccakHash('keccak256').update(this.pubKey).digest();
        // console.log('dist',dist);
        // var bits = dist.slice(-20);
        // //buff.toString('hex')
        // var address =bits.toString('hex');
        var address=this.tenderKeys.getAddressFromPrivKey(this._privKey.toString('hex'));
        return address;
  }

  // https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition
Wallet.prototype.toV3 = function (password, opts) {
    // assert(this._privKey, 'This is a public key only wallet')
    if(Buffer.isBuffer(opts)){
      console.log('need Buffer')
      return ;

    }
    //需要把这个函数里面的随机数提取出来
    var usersalt = crypto.randomBytes(16);
    var salt = bcrypt.genSaltSync(saltRounds,'a',usersalt);

    var hash = bcrypt.hashSync(password, salt);

    let hashs = crypto.createHash('sha256');
        hashs.update(Buffer.from(hash));
    let userkey = hashs.digest('hex');

    var userkeyF8 =tou8(Buffer.from(userkey,'hex') ) ;
    Amino.RegisterConcrete(null,'tendermint/PrivKeyEd25519');

    var prefixPrivKey = Amino.MarshalBinary('tendermint/PrivKeyEd25519',  this._privKey);
    var praviteFB = tou8(prefixPrivKey);


    var  cryptoResult = encryptSymmetric(praviteFB, '',  userkeyF8);
    
    
    return {
      address: this.getAddress().toString('hex'),
      crypto: {
        text:toBuffer(cryptoResult).toString('hex'),
        params: {
          salt:usersalt.toString('hex') 
        }
      },
      cipher:'bcrypt'
    }
  }
  
  Wallet.prototype.getV3Filename = function (timestamp) {
    /*
     * We want a timestamp like 2016-03-15T17-11-33.007598288Z. Date formatting
     * is a pain in Javascript, everbody knows that. We could use moment.js,
     * but decide to do it manually in order to save space.
     *
     * toJSON() returns a pretty close version, so let's use it. It is not UTC though,
     * but does it really matter?
     *
     * Alternative manual way with padding and Date fields: http://stackoverflow.com/a/7244288/4964819
     *
     */
    var ts = timestamp ? new Date(timestamp) : new Date()
  
    return [
      'UTC--',
      ts.toJSON().replace(/:/g, '-'),
      '--',
      this.getAddress().toString('hex')
    ].join('')
  }
  
  Wallet.prototype.toV3String = function (password, opts) {
    return JSON.stringify(this.toV3(password, opts))
  }


  Wallet.fromPrivateKey = function (priv) {
    return new Wallet(priv)
  }


  Wallet.fromV3 = function (input, password, nonStrict) {
    
    var json = (typeof input === 'object') ? input : JSON.parse(nonStrict ? input.toLowerCase() : input)
    // {
    //   "address": "2BFC8C8C0554102A9683C77943E15F25E74FB259",
    //   "crypto": {
    //     "text": "22e6fcf25938a2e86b93a5e134cf11e42d40f07910da61ac68bc107d89cb700338fa37f375a66ceb879006fa0ff97b052306aad901aed33c17da7f2382560cc0a4bd4c8f0fba4575cb4e4825e93542677f71390b287c943ab580b8c314bea6503995a29b215e8687809c4d2644",
    //     "params": {
    //       "salt": "a0b1e2a01b216d1ef0fbffa61d359db1"
    //     }
    //   },
    //   "cipher": "bcrypt"
    // }
    var usersalt,msghex;
    try{
      usersalt = json.crypto.params.salt;
       msghex = json.crypto.text;

    }
    catch(ex){
     console.log(ex)

    }
    if(usersalt==undefined||msghex==undefined){
      return ;
    }
    

    var salt = bcrypt.genSaltSync(saltRounds,'a',Buffer.from(usersalt,'hex') );

    var hash = bcrypt.hashSync(password, salt);

    let hashs = crypto.createHash('sha256');
        hashs.update(Buffer.from(hash));
    let userkey = hashs.digest('hex');

    var userkeyF8 =tou8(Buffer.from(userkey,'hex') ) ;
    var msghexF8 =tou8(Buffer.from(msghex,'hex') ) ;
    var seed = decryptSymmetric(msghexF8,'', userkeyF8)
    seed = toBuffer(seed);
    Amino.RegisterConcrete(null,'tendermint/PrivKeyEd25519');

    var seed = Amino.unMarshalBinary('tendermint/PrivKeyEd25519',  seed);


    console.log('seed')
    console.log(seed)
    
    
  
    return new Wallet(seed)
  }
  

  module.exports = Wallet