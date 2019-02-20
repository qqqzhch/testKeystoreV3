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

function MarshalBinary( message) {
  let prefixBytes = 'tendermint/PrivKeyEd25519';
  prefixBytes = Buffer.from(prefixBytes.concat(message.length));
  prefixBytes = Buffer.concat([prefixBytes, message]);
  return prefixBytes
}

function unMarshalBinary(message) {
  let prefixBytes = 'tendermint/PrivKeyEd25519';
  prefixBytes = Buffer.from(prefixBytes.concat(message.length));
  prefixBytes = Buffer.concat([prefixBytes, message]);
  return prefixBytes
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
    var praviteFB = tou8(MarshalBinary(this._privKey));

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
  
    if (json.version !== 3) {
      throw new Error('Not a V3 wallet')
    }
  
    var derivedKey
    var kdfparams
    if (json.crypto.kdf === 'bcrypt') {
      kdfparams = json.crypto.kdfparams
  
      // FIXME: support progress reporting callback
      // derivedKey = scryptsy(Buffer.from(password), Buffer.from(kdfparams.salt, 'hex'), kdfparams.n, kdfparams.r, kdfparams.p, kdfparams.dklen)
      var saltbcrypt = bcrypt.genSaltSync(saltRounds);
      derivedKey= bcrypt.hashSync(Buffer.from(password), saltbcrypt);

    } else if (json.crypto.kdf === 'pbkdf2') {
      kdfparams = json.crypto.kdfparams
  
      if (kdfparams.prf !== 'hmac-sha256') {
        throw new Error('Unsupported parameters to PBKDF2')
      }
  
      derivedKey = crypto.pbkdf2Sync(Buffer.from(password), Buffer.from(kdfparams.salt, 'hex'), kdfparams.c, kdfparams.dklen, 'sha256')
    } else {
      throw new Error('Unsupported key derivation scheme')
    }
  
    var ciphertext = Buffer.from(json.crypto.ciphertext, 'hex')
  
    var mac = ethUtil.keccak256(Buffer.concat([ derivedKey.slice(16, 32), ciphertext ]))
    if (mac.toString('hex') !== json.crypto.mac) {
      throw new Error('Key derivation failed - possibly wrong passphrase')
    }
  
    var decipher = crypto.createDecipheriv(json.crypto.cipher, derivedKey.slice(0, 16), Buffer.from(json.crypto.cipherparams.iv, 'hex'))
    var seed = runCipherBuffer(decipher, ciphertext)
    
  
    return new Wallet(seed)
  }
  

  module.exports = Wallet