var ETHv3wallet=require('./ETHv3wallet');



// var pravite=Buffer.from("a328891040a63d89fa2af64b52df87139ea2df44470fd713731a483934d61af1df03f4488c5b0ee06d34187d1df49f6df1ccbb5f7a74b0375b41073211a8b2b08647389b8c",'hex') ;

// pravite.slice(-128);

// return 
var pravite=Buffer.from("e056050a43395f3c08dbca5a6436632c9f8334355f33a166cb4187f427985d2e95956644e20329873bdd36d68f4d8ce177d13b68daadaff2322a6d8a6307106f",'hex') ;


console.log(pravite.length);
console.log(pravite.toString('hex').length);

var wallet =new ETHv3wallet(pravite);
console.log('pubKey',wallet.pubKey)
const myPlaintextPassword = '123456';
var result = wallet.toV3(myPlaintextPassword);

console.log(JSON.stringify(result));
console.log('----------------')
var  myoldwallet = ETHv3wallet.fromV3(result,myPlaintextPassword);
// console.log(myoldwallet)

var ss = myoldwallet._privKey.toString('hex');
console.log('private',ss)
console.log('pubKey',myoldwallet.pubKey)
