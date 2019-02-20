const bcrypt = require('bcrypt');

const saltRounds = 12;
const myPlaintextPassword = '123456';
var crypto    = require("crypto");

var nacl = require('tweetnacl')
nacl.util = require('tweetnacl-util')

var tou8 = require('buffer-to-uint8array');
var toBuffer = require('typedarray-to-buffer')



var salt = bcrypt.genSaltSync(saltRounds,'a');
var hash = bcrypt.hashSync(myPlaintextPassword, salt);
console.log( 'hash')
console.log( hash)
console.log(Buffer.from(hash).toString('hex') )


// var bf= Buffer.from('243261243132245755446657554466575544665755446657554466574f4162572f697944457576567a322e663947756c4255586e31556c4175436753','hex')
// console.log(bf.toString()) 
//  console.log('l hash')
//  console.log(hash)

let hashs = crypto.createHash('sha256');
        hashs.update(Buffer.from(hash));
let result = hashs.digest('hex');

console.log('result');
console.log(result);

var key=hashs;
var pravite=Buffer.from("a328891040a63d89fa2af64b52df87139ea2df44470fd713731a483934d61af1df03f4488c5b0ee06d34187d1df49f6df1ccbb5f7a74b0375b41073211a8b2b08647389b8c",'hex') ;

//https://www.npmjs.com/package/crypto-js

// var CryptoJS = require("crypto-js");
// console.log(CryptoJS.HmacSHA1("Message", "Key"));

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


  
  var resultB =tou8(Buffer.from(result,'hex') ) ;
  var praviteB = tou8(pravite);
  var prefix = new Buffer('minute-k');
  var prefixB = tou8(prefix);
  console.log('====')
  console.log(result)
  console.log('resultB',resultB,resultB.length)
  console.log('praviteB',praviteB,praviteB.length)
  console.log('*****')
  console.log(hashs)

  console.log('====')
console.log(resultB.length)
  var  data = encryptSymmetric(praviteB, '',  resultB);
  console.log('- -')
  console.log(data,data.length)

  var praviteB2 =  decryptSymmetric(data,'',resultB);
  console.log('praviteB2',praviteB2)
  if(praviteB2==praviteB){
      console.log('0k')
  }else{
    console.log('no')
    var p2 = toBuffer(praviteB2).toString('hex')
    var p1 = toBuffer(praviteB).toString('hex')
    console.log(p1)
    console.log(p2)
  }

  
  