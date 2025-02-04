const { Hash } = require("sha256");
const crypto = require("crypto");
const EC = require("elliptic").ec;
const ecdsa = new EC("secp256k1");
const { createHash } = require("crypto");
const { verify } = require("crypto");
const { sha256 } = require("./hashes");
const { parseDER, verifyECDSASignature } = require("./EcdsaVerification");

function toHex(value) {
  return value
    .toString(16)
    .padStart(
      value.toString(16).length % 2 === 0
        ? value.toString(16).length
        : value.toString(16).length + 1,
      "0"
    );
}

function littleEndian(data) {
  let pairs = [];
  for (let i = 0; i < data.length; i += 2) {
    pairs.unshift(data.substring(i, i + 2));
  }
  return pairs.join("");
}

function ripemd160(data) {
  const hash = crypto.createHash("ripemd160");
  hash.update(data);
  return hash.digest("hex");
}

function doubleHash(dataHex) {
  const firstHash = crypto
    .createHash("sha256")
    .update(Buffer.from(dataHex, "hex"))
    .digest("hex");
  const secondHash = crypto
    .createHash("sha256")
    .update(firstHash, "hex")
    .digest("hex");
  return secondHash;
}

function concVin(transaction) {
  let concatStr = "";
  transaction.vin.forEach((vin) => {
    const sigSize = vin.scriptsig.length / 2;
    concatStr +=
      littleEndian(vin.txid) +
      littleEndian(toHex(vin.vout).padStart(8, "0")) +
      sigSize.toString(16).padStart(2, "0") +
      vin.scriptsig +
      littleEndian(vin.sequence.toString(16));
  });
  return concatStr;
}

function concVout(transaction) {
  let concatStr = "";
  transaction.vout.forEach((vout) => {
    concatStr +=
      littleEndian(vout.value.toString(16).padStart(16, "0")) +
      toHex(vout.scriptpubkey.length / 2)
        .toString(16)
        .padStart(2, "0") +
      vout.scriptpubkey;
  });
  return concatStr;
}

function serializeTransaction(transaction) {
  const serializeTransaction =
    littleEndian(transaction.version.toString(16).padStart(8, "0")) +
    toHex(transaction.vin.length).padStart(2, "0") +
    concVin(transaction) +
    transaction.vout.length.toString(16).padStart(2, "0") +
    concVout(transaction) +
    littleEndian(toHex(transaction.locktime)).padEnd(8, "0");
  return doubleHash(serializeTransaction);
}

function verifyFiles(data) {
  const data1 = littleEndian(serializeTransaction(data));
  const dataBytes = Buffer.from(data1, "hex");
  return crypto.createHash("sha256").update(dataBytes).digest("hex") + ".json";
}

function createVinDigest(transaction, index) {
  let concatStr = "";
  const vin = transaction.vin;
  vin.forEach((vin, i) => {
    if (i === index) {
      concatStr +=
        littleEndian(vin.txid) +
        littleEndian(toHex(vin.vout).padStart(8, "0")) +
        littleEndian(
          toHex(vin.prevout.scriptpubkey.length / 2).padStart(2, "0")
        ) +
        vin.prevout.scriptpubkey +
        littleEndian(toHex(vin.sequence));
    } else {
      concatStr +=
        littleEndian(vin.txid) +
        littleEndian(toHex(vin.vout).padStart(8, "0")) +
        "00" +
        littleEndian(toHex(vin.sequence));
    }
  });
  return concatStr;
}

function createDigest(transaction, index) {
  const concatStr =
    littleEndian(transaction.version.toString(16).padStart(8, "0")) +
    toHex(transaction.vin.length).padStart(2, "0") +
    createVinDigest(transaction, index) +
    transaction.vout.length.toString(16).padStart(2, "0") +
    concVout(transaction) +
    littleEndian(toHex(transaction.locktime)).padEnd(8, "0") +
    "01000000";
  return doubleHash(concatStr);
}

function checkSigP2PKH(transaction, i) {
  const message = createDigest(transaction, i);
  const isValid = verifyECDSASignature(
    transaction.vin[i].scriptsig_asm.split(" ")[3],
    transaction.vin[i].scriptsig_asm.split(" ")[1],
    message
  );
  if (isValid) {
    console.log("yes");
  }
}

function checkStack(transaction) {
  let index = 0;
  const vin = transaction.vin;
  for (const vin_entry of vin) {
    const stack = [];
    const vin_asm = vin_entry.scriptsig_asm.split(" ");

    stack.push(vin_asm[1]);

    stack.push(vin_asm[3]);
    const script = vin_entry.prevout.scriptpubkey_asm.split(" ");
    for (let i = 0; i < script.length; i++) {
      if (script[i] === "OP_DUP") {
        stack.push(stack[stack.length - 1]);
        // console.log(stack);
      } else if (script[i] === "OP_HASH160") {
        stack.pop();
        const data = crypto
          .createHash("sha256")
          .update(Buffer.from(stack[stack.length - 1], "hex"))
          .digest();
        const hexHashedValue = ripemd160(data);
        // console.log(hexHashedValue);
        stack.push(hexHashedValue);
        // console.log(stack);
      } else if (script[i] === "OP_PUSHBYTES_20") {
        stack.push(script[i + 1]);
        // console.log(stack);
      } else if (script[i] === "OP_EQUALVERIFY") {
        // console.log(stack[stack.length - 1], stack[stack.length - 2]);
        if (stack[stack.length - 1] === stack[stack.length - 2]) {
          stack.pop();
          stack.pop();
        } else {
          return false;
        }
        // console.log(stack);
      } else if (script[i] === "OP_CHECKSIG") {
        // console.log("*****");
        const msgDigest = createDigest(transaction, index);
        // console.log(msgDigest + "      ******* ");
        const pubkey = stack.pop();
        // console.log(pubkey);
        const signature = stack.pop();
        // console.log(signature);
        const isValid = verifyECDSASignature(pubkey, signature, msgDigest);
        // console.log(stack);
      }
    }
    index++;
  }
  return true;
}

module.exports = {
  verifyFiles,
  checkStack,
  verifyECDSASignature,
  createDigest,
  parseDER,
  checkSigP2PKH,
  createVinDigest,
  serializeTransaction,
  concVout,
  concVin,
  doubleHash,
  littleEndian,
  ripemd160,
  toHex,
};

// console.log(littleEndian(serializeTransaction(tx)));
