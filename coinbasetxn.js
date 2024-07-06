const {
  serializeTransaction,
  littleEndian,
  verifyFiles,
  doubleHash,
  checkSigP2PKH,
  checkStack,
} = require("./functions");
const { create_wtxid } = require("./wtxid.js");
const { sha256 } = require("./hashes.js");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { checkSig_p2wpkh } = require("./p2wpkh.js");
const { calculateTransactionWeight } = require("./txweight.js");
const { p2pkh } = require("bitcoinjs-lib/src/payments/p2pkh.js");

let wtxns = [];
let txAll = [];

//checking

// directory where the files are stored
const directory = "./mempool";

// function to generate the merkle root
const generateMerkleRoot = (txids) => {
  if (txids.length === 0) return null;

  // reverse the txids
  let level = txids.map((txid) => Buffer.from(littleEndian(txid), "hex"));

  while (level.length > 1) {
    const nextLevel = [];

    for (let i = 0; i < level.length; i += 2) {
      let pairHash;
      if (i + 1 === level.length) {
        // In case of an odd number of elements, duplicate the last one
        pairHash = doubleHash(Buffer.concat([level[i], level[i]]));
      } else {
        pairHash = doubleHash(Buffer.concat([level[i], level[i + 1]]));
      }
      nextLevel.push(Buffer.from(pairHash, "hex"));
    }

    level = nextLevel;
  }

  return level[0].toString("hex");
};

// function to generate the coinbase transaction
function generate_coinbase_tx(wtxns) {
  wtxns.unshift("0".padStart(64, "0"));
  console.log("wtxns", wtxns);
  console.log("wmkrlrt", generateMerkleRoot(wtxns));
  const witness_commitment = generate_witness_commitment(
    generateMerkleRoot(wtxns)
  );
  console.log("wcom", witness_commitment);
  const scriptpubkey = "6a24aa21a9ed" + witness_commitment.toString("hex"); // Concatenate with the hexadecimal string of witness_commitment
  const scriptsig =
    "49366144657669436872616E496C6F7665426974636F696E4D696E696E67"; // coinbase scriptSig
  let coinbase_tx = "";
  coinbase_tx += "01000000"; // version
  // 8
  coinbase_tx += "0001"; // marker + flag //4
  // 12
  coinbase_tx += "01"; // number of inputs //2
  // 14
  coinbase_tx +=
    "0000000000000000000000000000000000000000000000000000000000000000"; //64
  // 78
  coinbase_tx += "ffffffff"; // previous output // 8
  // 86
  coinbase_tx +=
    "25246920616d206e61726173696d686120616e64206920616d20736f6c76696e672062697463"; // coinbase scriptSig // 37
  coinbase_tx += "ffffffff"; // sequence
  coinbase_tx += "02"; // number of outputs

  //output 1
  coinbase_tx += "f595814000000000"; // value - 1
  coinbase_tx += "19"; // size of scriptpubkey
  coinbase_tx += "76a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac"; // scriptpubkey

  //output 2
  coinbase_tx += "0000000000000000"; // value - 2
  coinbase_tx +=
    (scriptpubkey.length / 2).toString(16).padStart("0", 2) + scriptpubkey; // scriptpubkey
  coinbase_tx += "01"; // number of witnesses
  coinbase_tx += "20"; // size of witness commitment
  coinbase_tx +=
    "0000000000000000000000000000000000000000000000000000000000000000";
  coinbase_tx += "00000000"; // locktime
  return coinbase_tx;
}

function generate_witness_commitment(W_merkleroot) {
  return doubleHash(W_merkleroot + "0".padStart(64, "0"));
}

function checkp2pkh(tx) {
  for (let i = 0; i < tx.vin.length; i++) {
    // console.log(tx.vin[i].prevout.scriptpubkey_type == "p2pkh")
    if (tx.vin[i].prevout.scriptpubkey_type != "p2pkh") {
      return false;
    }
  }
  return true;
}

function checkp2wpkh(tx) {
  for (let i = 0; i < tx.vin.length; i++) {
    // console.log(tx.vin[i].prevout.scriptpubkey_type)
    if (tx.vin[i].prevout.scriptpubkey_type != "v0_p2wpkh") {
      return false;
    }
  }
  return true;
}

// read all the files in the directory
const targetweight = 4 * 1000 * 1000;
let weightTill = 320; // block weight
try {
  const files = fs.readdirSync(directory);
  for (const filename of files) {
    const filepath = path.join(directory, filename);
    const fileData = fs.readFileSync(filepath, "utf8");
    const data = JSON.parse(fileData);
    const transactionType = data.vin[0].prevout.scriptpubkey_type;
    const fileVerification = verifyFiles(data);
    if (transactionType === "p2pkh") {
      if (checkp2pkh(data)) {
        if (filename === fileVerification) {
          if (checkStack(data)) {
            if (calculateTransactionWeight(data)) {
              weightTill += calculateTransactionWeight(data); // calculating the transaction weight
              if (weightTill < targetweight) {
                wtxns.push(littleEndian(serializeTransaction(data))); //pushing the little endain form of the normal txid
                txAll.push(littleEndian(serializeTransaction(data)));
              } else {
                weightTill += calculateTransactionWeight(data); // calculating the transaction weight
                break;
              }
            }
          }
        }
      }
    }

    if (transactionType === "v0_p2wpkh") {
      if (checkp2wpkh(data)) {
        if (filename === fileVerification) {
          if (checkSig_p2wpkh(data)) {
            if (calculateTransactionWeight(data)) {
              weightTill += calculateTransactionWeight(data); // calculating the transaction weight
              if (weightTill < targetweight) {
                wtxns.push(littleEndian(create_wtxid(data))); //pushing the little endain form of the wtxid
                txAll.push(littleEndian(serializeTransaction(data)));
              } else {
                weightTill += calculateTransactionWeight(data); // calculating the transaction weight
                break;
              }
            }
          }
        }
      }
    }
  }
} catch (err) {
  console.error("Error:", err);
}

const coinbase_tx = generate_coinbase_tx(wtxns); //created coinbase transaction

txAll.unshift(littleEndian(doubleHash(coinbase_tx))); // added the coinbase transaction to the txns array

const merkleroot = generateMerkleRoot(txAll); // merkle root of the txns array

module.exports = { merkleroot, txAll, coinbase_tx }; //exporting the merkle root and txns array
