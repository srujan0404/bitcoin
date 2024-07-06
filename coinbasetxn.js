const {
  serializeP2pkh,
  littleEndian,
  verifyFiles,
  doubleHash,
} = require("./functions");
const { create_wtxid } = require("./wtxid.js");
const { sha256 } = require("./hashes.js");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

let txns = [];
let wtxns = [];

// directory where the files are stored
const directory = "code-challenge-2024-cherry-1729-9090/mempool";

// function to generate the merkle root
const generateMerkleRoot = (txids) => {
  if (txids.length === 0) return null;

  // reverse the txids
  let level = txids.map((txid) =>
    Buffer.from(txid, "hex").reverse().toString("hex")
  );

  while (level.length > 1) {
    const nextLevel = [];

    for (let i = 0; i < level.length; i += 2) {
      let pairHash;
      if (i + 1 === level.length) {
        // In case of an odd number of elements, duplicate the last one
        pairHash = doubleHash(level[i] + level[i]);
      } else {
        pairHash = doubleHash(level[i] + level[i + 1]);
      }
      nextLevel.push(pairHash);
    }

    level = nextLevel;
  }

  return level[0];
};

// read all the files in the directory
try {
  const files = fs.readdirSync(directory);

  for (const filename of files) {
    const filepath = path.join(directory, filename);
    const fileData = fs.readFileSync(filepath, "utf8");
    const data = JSON.parse(fileData);
    const transactionType = data.vin[0].prevout.scriptpubkey_type;
    const fileVerification = verifyFiles(data);
    if (transactionType === "p2pkh") {
      if (filename === fileVerification) {
        txns.push(littleEndian(doubleHash(serializeP2pkh(data)))); //pushing the little endain form of the normal txid
      }
    }

    if (transactionType === "v0_p2wpkh") {
      if (filename === fileVerification) {
        wtxns.push(littleEndian(create_wtxid(data))); //pushing the little endain form of the wtxid
      }
    }
  }
} catch (err) {
  console.error("Error:", err);
}

// write all the wtxns to a file
const fileName = "wtxns.txt";
const fileContent = `wtxns:\n[${wtxns
  .map((item) => `\n  "${item}"`)
  .join(",")}\n]`;
fs.writeFile(fileName, fileContent, (err) => {
  if (err) {
    console.error("Error writing to file:", err);
  } else {
    // console.log(`File "${fileName}" created successfully with wtxins as list.`);
  }
});

//write all the txns to a file
const fileName2 = "txns.txt";
const fileContent2 = `txns:\n[${txns
  .map((item) => `\n  "${item}"`)
  .join(",")}\n]`;
fs.writeFile(fileName2, fileContent2, (err) => {
  if (err) {
    console.error("Error writing to file:", err);
  } else {
    // console.log(`File "${fileName2}" created successfully with txins as list.`);
  }
});

// function to generate the coinbase transaction
function generate_coinbase_tx(wtxns) {
  const witness_commitment = generate_witness_commitment(
    generateMerkleRoot(wtxns)
  );
  const scriptpubkey = "6a24aa21a9ed" + witness_commitment.toString("hex"); // Concatenate with the hexadecimal string of witness_commitment
  const scriptsig =
    "49366144657669436872616E496C6F7665426974636F696E4D696E696E67";

  let coinbase_tx = "";
  coinbase_tx += "01000000"; // version
  coinbase_tx += "0010"; // marker + flag
  coinbase_tx += "01"; // number of inputs
  coinbase_tx +=
    "0000000000000000000000000000000000000000000000000000000000000000";
  coinbase_tx += "ffffffff"; // previous output
  coinbase_tx += scriptsig.toString(16).length / 2 + scriptsig; // scriptsig
  coinbase_tx += "ffffffff"; // sequence
  coinbase_tx += "02"; // number of outputs
  coinbase_tx += "00f2052a01000000"; // value - 1
  coinbase_tx += "19"; // size of scriptpubkey
  coinbase_tx += "76a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac"; // scriptpubkey
  coinbase_tx += "0000000000000000"; // value - 2
  coinbase_tx += scriptpubkey.length / 2 + scriptpubkey; // scriptpubkey
  coinbase_tx += "01"; // number of witnesses
  coinbase_tx += "20"; // size of witness commitment
  coinbase_tx +=
    "0000000000000000000000000000000000000000000000000000000000000000";
  coinbase_tx += "00000000"; // locktime
  const witness_commitment = generate_witness_commitment(
    generateMerkleRoot(wtxns)
  );
  console.log("wcom", witness_commitment);
  const scriptpubkey = "6a24aa21a9ed" + witness_commitment.toString("hex"); // Concatenate with the hexadecimal string of witness_commitment
  const scriptsig =
    "49366144657669436872616E496C6F7665426974636F696E4D696E696E67"; // coinbase scriptSig
  let coinbase_tx = "";
  coinbase_tx += "01000000"; // version
  return coinbase_tx;
}
const scriptpubkey = '6a24aa21a9ed' + witness_commitment.toString(); // Concatenate with the hexadecimal string of witness_commitment

function generate_witness_commitment(wtxidhash) {
  return doubleHash(
    "0000000000000000000000000000000000000000000000000000000000000000" +
      wtxidhash
  );
}

const coinbase_tx = generate_coinbase_tx(wtxns); //created coinbase transaction
txns.unshift(coinbase_tx); // added the coinbase transaction to the txns array

const merkleroot = generateMerkleRoot(txns); // merkle root of the txns array
const witnesscommitment = generate_witness_commitment(merkleroot); // witness commitment of the merkle root

console.log(coinbase_tx);
module.exports = { merkleroot, txns, coinbase_tx }; //exporting the merkle root and txns array

tx = {
  version: 2,
  locktime: 832539,
  coinbase_tx += "25246920616d206e61726173696d686120616e64206920616d20736f6c76696e672062697463"; // coinbase scriptSig // 37
  vin: [
    {
      txid: "7c218cbf0fe023d15b71e401b34d6841f3cdf5617a42eddf32708fcf4c3236cb",
      vout: 0,
      prevout: {
        scriptpubkey: "76a9144e30f8fd336a83e1d6910fb9713d21f6dda1ff5a88ac",
        scriptpubkey_asm:
          "OP_DUP OP_HASH160 OP_PUSHBYTES_20 4e30f8fd336a83e1d6910fb9713d21f6dda1ff5a OP_EQUALVERIFY OP_CHECKSIG",
        scriptpubkey_type: "p2pkh",
        scriptpubkey_address: "188SNe6fRhVm2hd3PZ3TwsBSWchFZak2Th",
        value: 36882,
      },
      scriptsig:
        "47304402202bce610e94ec86bcdda2622158bd021640722acbbbb506cc11fb3c1a10b5d562022014bd28a276f44a86b9987daa0555525d60f602b2f52ef4bd4e07f9bad8041b6c01210227ce4c39213f865f1c18987079557548748e83126fcc11293fbd8eac4b0671eb",
      scriptsig_asm:
        "OP_PUSHBYTES_71 304402202bce610e94ec86bcdda2622158bd021640722acbbbb506cc11fb3c1a10b5d562022014bd28a276f44a86b9987daa0555525d60f602b2f52ef4bd4e07f9bad8041b6c01 OP_PUSHBYTES_33 0227ce4c39213f865f1c18987079557548748e83126fcc11293fbd8eac4b0671eb",
      is_coinbase: false,
      sequence: 4294967293,
    },
    {
      txid: "869b62369426bac43369b49e62f5611f94f808a7c670875831c7f593eb7b5ba9",
      vout: 0,
      prevout: {
        scriptpubkey: "76a914d74bce8fd3488eed4d449351feafdaca1d03b7d688ac",
        scriptpubkey_asm:
          "OP_DUP OP_HASH160 OP_PUSHBYTES_20 d74bce8fd3488eed4d449351feafdaca1d03b7d6 OP_EQUALVERIFY OP_CHECKSIG",
        scriptpubkey_type: "p2pkh",
        scriptpubkey_address: "1LdP6Q62wHkZwoBE62Gy4y2tuw9kZhTqmv",
        value: 328797,
      },
      scriptsig:
        "473044022019d625e3d2a77df31515113790c90c2f00e9200b22010717329a878246c9881e02203970dafda92f72cf3d8579509907e41099e9bdd6f3541eb46a6806697f407dd2012102a17743cdc1bf0f9adab350bba42658fca42c0d486ab0cc49e2451bb5be2295a7",
      scriptsig_asm:
        "OP_PUSHBYTES_71 3044022019d625e3d2a77df31515113790c90c2f00e9200b22010717329a878246c9881e02203970dafda92f72cf3d8579509907e41099e9bdd6f3541eb46a6806697f407dd201 OP_PUSHBYTES_33 02a17743cdc1bf0f9adab350bba42658fca42c0d486ab0cc49e2451bb5be2295a7",
      is_coinbase: false,
      sequence: 4294967293,
    },
    {
      txid: "c0f0cf3896308fabf365f9430a5d42265efe4b9bda12f61e5146c21aed1b88f6",
      vout: 0,
      prevout: {
        scriptpubkey: "76a9143b5428c5c51348a788afd5cc362f227d4c04c66288ac",
        scriptpubkey_asm:
          "OP_DUP OP_HASH160 OP_PUSHBYTES_20 3b5428c5c51348a788afd5cc362f227d4c04c662 OP_EQUALVERIFY OP_CHECKSIG",
        scriptpubkey_type: "p2pkh",
        scriptpubkey_address: "16Qhgomq9Jnh247Q5KCzXvLXhZv1VBzTrS",
        value: 34100,
      },
      scriptsig:
        "473044022034fdb2fdcf5b147f81c4a13350e9ee8c9f5de08d27103cf65e6a7c3b96042d2202206186ce4aa966c16e4671a35f766c17382c9c758d1622ef59bba6ef571c679f7a012103d23ad1dccc41cf313e2355fe220238260efde1fc156a9c4f7211898229db1139",
      scriptsig_asm:
        "OP_PUSHBYTES_71 3044022034fdb2fdcf5b147f81c4a13350e9ee8c9f5de08d27103cf65e6a7c3b96042d2202206186ce4aa966c16e4671a35f766c17382c9c758d1622ef59bba6ef571c679f7a01 OP_PUSHBYTES_33 03d23ad1dccc41cf313e2355fe220238260efde1fc156a9c4f7211898229db1139",
      is_coinbase: false,
      sequence: 4294967293,
    },
    {
      txid: "f4482b2a061a321965c7ad1768fc80599ce36fbf693cfd95d23dd708e22c45cc",
      vout: 0,
      prevout: {
        scriptpubkey: "76a914529a520fba93f9940fc113c803e04fb8e378af1c88ac",
        scriptpubkey_asm:
          "OP_DUP OP_HASH160 OP_PUSHBYTES_20 529a520fba93f9940fc113c803e04fb8e378af1c OP_EQUALVERIFY OP_CHECKSIG",
        scriptpubkey_type: "p2pkh",
        scriptpubkey_address: "18XmH7PEgjmBLqeee2nSSV6Qm5C5x2JNxs",
        value: 41184,
      },
      scriptsig:
        "47304402207d9a086b835659c2f45de8d2d85292f04ce8b833969cdd4f352b679a7b3775940220050cfec89f5a309799f3dc0628ff20fb696c43b1c6bee93066dfdab089da50b301210281e3301ea2655d695a1950f59456b27f8f3fbc0bbe6349cedc4121052a36b816",
      scriptsig_asm:
        "OP_PUSHBYTES_71 304402207d9a086b835659c2f45de8d2d85292f04ce8b833969cdd4f352b679a7b3775940220050cfec89f5a309799f3dc0628ff20fb696c43b1c6bee93066dfdab089da50b301 OP_PUSHBYTES_33 0281e3301ea2655d695a1950f59456b27f8f3fbc0bbe6349cedc4121052a36b816",
      is_coinbase: false,
      sequence: 4294967293,
    },
  ],
  vout: [
    {
      scriptpubkey: "76a914090a212ddb7211158409534bce9f6d553bcd028788ac",
      scriptpubkey_asm:
        "OP_DUP OP_HASH160 OP_PUSHBYTES_20 090a212ddb7211158409534bce9f6d553bcd0287 OP_EQUALVERIFY OP_CHECKSIG",
      scriptpubkey_type: "p2pkh",
      scriptpubkey_address: "1poDYYTsXhXimWRiKRjVCokoLzzbjR25q",
      value: 24200,
    },
    {
      scriptpubkey: "a914f15ac47ae6eb8f8da450ba7787b6a8c0059b076087",
      scriptpubkey_asm:
        "OP_HASH160 OP_PUSHBYTES_20 f15ac47ae6eb8f8da450ba7787b6a8c0059b0760 OP_EQUAL",
      scriptpubkey_type: "p2sh",
      scriptpubkey_address: "3PhBWQp766Lr5p4HqWFkEsMraLW2h918LV",
      value: 410000,
    },
  ],
};

const generateMerkleRoot = (txids) => {
    if (txids.length === 0) return null

  // reverse the txids
  let level = txids.map((txid) => Buffer.from(txid, 'hex').reverse().toString('hex'))

  while (level.length > 1) {
    const nextLevel = []

    for (let i = 0; i < level.length; i += 2) {
      let pairHash
      if (i + 1 === level.length) {
        // In case of an odd number of elements, duplicate the last one
        pairHash = doubleHash(level[i] + level[i])
      } else {
        pairHash = doubleHash(level[i] + level[i + 1])
      }
      nextLevel.push(pairHash)
    }

    level = nextLevel
  }

  return level[0]
  };


  // function to generate the coinbase transaction
  function generate_coinbase_tx(wtxns){
      const witness_commitment = generate_witness_commitment(generateMerkleRoot(wtxns));
      const scriptpubkey = '6a24aa21a9ed' + witness_commitment.toString('hex'); // Concatenate with the hexadecimal string of witness_commitment
      const scriptsig = "49366144657669436872616E496C6F7665426974636F696E4D696E696E67"

      let coinbase_tx = "";
      coinbase_tx += "01000000"; // version
      coinbase_tx += "0010"; // marker + flag
      coinbase_tx += "01"; // number of inputs
      coinbase_tx += "0000000000000000000000000000000000000000000000000000000000000000"
      coinbase_tx += "ffffffff"; // previous output
      coinbase_tx += scriptsig.toString(16).length/2 + scriptsig; // scriptsig
      coinbase_tx += "ffffffff"; // sequence
      coinbase_tx += "02"; // number of outputs

      //output 1
      coinbase_tx += "00f2052a01000000"; // value - 1
      coinbase_tx += "19" // size of scriptpubkey
      coinbase_tx += "76a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac"; // scriptpubkey

      //output 2
      coinbase_tx += "0000000000000000" // value - 2
      coinbase_tx += scriptpubkey.length/2 + scriptpubkey; // scriptpubkey
  }

  function generateMerkleRoot(txids) {
    let hashes = txids.map((txid) =>
      Buffer.from(txid.match(/../g).reverse().join(""), "hex")
    );

    while (hashes.length > 1) {
      let newHashes = [];
      for (let i = 0; i < hashes.length; i += 2) {
        let left = hashes[i];
        let right = "";
        if (i + 1 === hashes.length) {
          right = left;
        } else {
          right = hashes[i + 1];
        }
        let hash = doubleHash(Buffer.concat([left, right]));
        newHashes.push(Buffer.from(hash, "hex"));
      }
      hashes = newHashes;
    }

    return hashes[0].toString("hex");
  };


  function generate_coinbase_tx(wtxns){
    wtxns.unshift('0'.padStart(64,'0')); 
    console.log("wtxns",wtxns)
    console.log("wmkrlrt",generateMerkleRoot(wtxns))
    const witness_commitment = generate_witness_commitment(generateMerkleRoot(wtxns));
      console.log("wcom",witness_commitment)
      const scriptpubkey = '6a24aa21a9ed' + witness_commitment.toString('hex'); // Concatenate with the hexadecimal string of witness_commitment
      const scriptsig = "49366144657669436872616E496C6F7665426974636F696E4D696E696E67"; // coinbase scriptSig
  }


  function checkp2pkh(tx){
    for(let i = 0;i < tx.vin.length;i++){
        // console.log(tx.vin[i].prevout.scriptpubkey_type == "p2pkh")
        if(tx.vin[i].prevout.scriptpubkey_type != "p2pkh"){
            return false;
        }
    }
    return true;
  }

  function checkp2wpkh(tx){
    for(let i = 0;i < tx.vin.length;i++){
        // console.log(tx.vin[i].prevout.scriptpubkey_type)
        if(tx.vin[i].prevout.scriptpubkey_type != "v0_p2wpkh"){
            return false;
        }
    }
    return true;
  }


   const transactionType = data.vin[0].prevout.scriptpubkey_type;
        const fileVerification = verifyFiles(data);
        if (transactionType === "p2pkh") {
            if(checkp2pkh(data)){
                if (filename === fileVerification) {
                    if (checkStack(data)){
                        if( calculateTransactionWeight(data)){
                            weightTill += calculateTransactionWeight(data); // calculating the transaction weight 
                            if(weightTill < targetweight){
                                wtxns.push(littleEndian(serializeP2pkh(data))); //pushing the little endain form of the normal txid
                                txAll.push(littleEndian(serializeP2pkh(data)));
                            }else{
                                weightTill += calculateTransactionWeight(data); // calculating the transaction weight
                                break;
                            }
                        }
                    }
                }
            }
        }

        if (transactionType === "v0_p2wpkh") {

            if(checkp2wpkh(data)){
                if (filename === fileVerification) {
                   if (checkSig_p2wpkh(data)){ 
                        if(calculateTransactionWeight(data)){
                            weightTill += calculateTransactionWeight(data); // calculating the transaction weight
                            if(weightTill < targetweight){
                                wtxns.push(littleEndian(create_wtxid(data))); //pushing the little endain form of the wtxid
                                txAll.push(littleEndian(serializeP2pkh(data)))
                            }
                            else{
                                weightTill += calculateTransactionWeight(data); // calculating the transaction weight
                                break;
                            }
                        }
                   }
                }
            }

        }

const { serializeTransaction, littleEndian, verifyFiles, doubleHash, checkSigP2PKH, checkStack } = require("./functions");

module.exports = { verifyFiles,checkStack,verifyECDSASignature,createDigest,parseDER,checkSigP2PKH,createVinDigest,serializeTransaction,concVout,concVin,doubleHash,littleEndian,ripemd160,toHex };

