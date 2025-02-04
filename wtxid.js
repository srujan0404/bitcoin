const { concVin, concVout, littleEndian } = require("./functions.js");

const { doubleHash } = require("./hashes.js");

function create_wtxid(tx) {
  return doubleHash(
    littleEndian(tx.version.toString().padStart(8, "0")) +
      "00" + //marker
      "01" + //flag
      tx.vin.length.toString().padStart(2, "0") + //number of inputs
      concVin(tx) + //inputs
      tx.vout.length.toString().padStart(2, "0") + //number of outputs
      concVout(tx) + //outputs
      conc_witness(tx) + //witness
      tx.locktime.toString().padStart(8, "0")
  ); //locktime
}

function conc_witness(tx) {
  let concstr = "";

  for (const vinEntry of tx.vin) {
    const witness = vinEntry.witness;

    if (witness) {
      // Check if witness is defined

      concstr += witness.length.toString().padStart(2, "0");

      for (const wit of witness) {
        concstr += (wit.length / 2).toString(16).padStart(2, "0") + wit;
      }
    }
  }

  return concstr;
}

tx = {
  "version": 2,
  "locktime": 0,
  "vin": [
    {
      "txid": "1162cd4bb37c4e2b6a5f3ff55fe5dc468e18778e3562720edbed4cee1ca790f7",
      "vout": 0,
      "prevout": {
        "scriptpubkey": "0014b2d46ba014a6ceeb9f52c4bd309b521400722014",
        "scriptpubkey_asm": "OP_0 OP_PUSHBYTES_20 b2d46ba014a6ceeb9f52c4bd309b521400722014",
        "scriptpubkey_type": "v0_p2wpkh",
        "scriptpubkey_address": "bc1qkt2xhgq55m8wh86jcj7npx6jzsq8ygq5jfh0t2",
        "value": 546
      },
      "scriptsig": "",
      "scriptsig_asm": "",
      "witness": [
        "3044022010e3634f20606e90eae596f708f94828fb2ce52d0aa5f0e417013480b3cee8f00220010bdb86754f54b5af6efa6edde6d56bc7236fde8c1e338cb63d2163300ec63783",
        "02d2fd34ce41e88b8ede38795932a55bc5cb35a5d62f7012bbf441c4272b9cb908"
      ],
      "is_coinbase": false,
      "sequence": 4294967295
    },
    {
      "txid": "ac8ca8d865b958dda442001505a152bbf28b7688b260c88e5d55c6bcaa68dbd6",
      "vout": 3,
      "prevout": {
        "scriptpubkey": "0014ce91edd1f5e310b9027bd06aaf24477516406b62",
        "scriptpubkey_asm": "OP_0 OP_PUSHBYTES_20 ce91edd1f5e310b9027bd06aaf24477516406b62",
        "scriptpubkey_type": "v0_p2wpkh",
        "scriptpubkey_address": "bc1qe6g7m504uvgtjqnm6p427fz8w5tyq6mzwcfafh",
        "value": 4999
      },
      "scriptsig": "",
      "scriptsig_asm": "",
      "witness": [
        "3045022100fa4c99c232e88866854ff93c61081595a51611e1bdc9a50406c8d3e0b0a9d9d302205fc0d7d2b8c6880934079cd76d11957e1396902aabb1040d8922d6fbb2df302281",
        "03b9bcae8a5c484676b2a3fffb15a623b98809a9fe1d22ef1ee137e3a363903afe"
      ],
      "is_coinbase": false,
      "sequence": 4294967295
    },
    {
      "txid": "b796dffdecf073f7078f174a30bc17f884b05083859fd0404c85a2f03f948aed",
      "vout": 4,
      "prevout": {
        "scriptpubkey": "a914572916855e4175478289d70c2b0c1e7eccef500187",
        "scriptpubkey_asm": "OP_HASH160 OP_PUSHBYTES_20 572916855e4175478289d70c2b0c1e7eccef5001 OP_EQUAL",
        "scriptpubkey_type": "p2sh",
        "scriptpubkey_address": "39dsw5KqPBqiqr5CjBDz2Vdq5wPBrujk4n",
        "value": 154784
      },
      "scriptsig": "160014e45f69ef326f32752f59335c53a77b70485b340c",
      "scriptsig_asm": "OP_PUSHBYTES_22 0014e45f69ef326f32752f59335c53a77b70485b340c",
      "witness": [
        "304402200f7f141e06fbba9919aec5b8a6b8ab59f5392500b1f0fa1f2521e672c648308b02201245c4051aad813dc51334bf9ea5205714bf32be6c5fd6253e28ff9b5c0e4be901",
        "035b46fd00de98257d1ed860a9395170316fbbde456fa60f97dcf70cfd560ead7a"
      ],
      "is_coinbase": false,
      "sequence": 4294967295,
      "inner_redeemscript_asm": "OP_0 OP_PUSHBYTES_20 e45f69ef326f32752f59335c53a77b70485b340c"
    }
  ],
  "vout": [
    {
      "scriptpubkey": "0014b2d46ba014a6ceeb9f52c4bd309b521400722014",
      "scriptpubkey_asm": "OP_0 OP_PUSHBYTES_20 b2d46ba014a6ceeb9f52c4bd309b521400722014",
      "scriptpubkey_type": "v0_p2wpkh",
      "scriptpubkey_address": "bc1qkt2xhgq55m8wh86jcj7npx6jzsq8ygq5jfh0t2",
      "value": 8547
    },
    {
      "scriptpubkey": "6a01520a0080c7b5e38a23866802",
      "scriptpubkey_asm": "OP_RETURN OP_PUSHBYTES_1 52 OP_PUSHBYTES_10 0080c7b5e38a23866802",
      "scriptpubkey_type": "op_return",
      "value": 0
    },
    {
      "scriptpubkey": "512015f5cab2f9e2c9e634a53223314ca0305fb9f1126fc74ab73b0d534708331837",
      "scriptpubkey_asm": "OP_PUSHNUM_1 OP_PUSHBYTES_32 15f5cab2f9e2c9e634a53223314ca0305fb9f1126fc74ab73b0d534708331837",
      "scriptpubkey_type": "v1_p2tr",
      "scriptpubkey_address": "bc1pzh6u4vheuty7vd99xg3nzn9qxp0mnugjdlr54demp4f5wzpnrqms6vawdq",
      "value": 546
    },
    {
      "scriptpubkey": "001456842e8539efe5d08cf67e536fdeb89f6fc9c00b",
      "scriptpubkey_asm": "OP_0 OP_PUSHBYTES_20 56842e8539efe5d08cf67e536fdeb89f6fc9c00b",
      "scriptpubkey_type": "v0_p2wpkh",
      "scriptpubkey_address": "bc1q26zzapfealjapr8k0efklh4cnahunsqt6ayx0x",
      "value": 9998
    },
    {
      "scriptpubkey": "a914572916855e4175478289d70c2b0c1e7eccef500187",
      "scriptpubkey_asm": "OP_HASH160 OP_PUSHBYTES_20 572916855e4175478289d70c2b0c1e7eccef5001 OP_EQUAL",
      "scriptpubkey_type": "p2sh",
      "scriptpubkey_address": "39dsw5KqPBqiqr5CjBDz2Vdq5wPBrujk4n",
      "value": 135804
    }
  ]
}

module.exports = { create_wtxid };


function create_wtxid(tx) {
  return doubleHash(
    littleEndian(tx.version.toString(16).padStart(8, "0")) +
      "00" + //marker
      "01" + //flag
      tx.vin.length.toString(16).padStart(2, "0") + //number of inputs
      concVin(tx) + //inputs
      tx.vout.length.toString(16).padStart(2, "0") + //number of outputs
      concVout(tx) + //outputs
      conc_witness(tx) + //witness
      littleEndian(tx.locktime.toString(16).padStart(8, "0"))
  ); //locktime
}

function conc_witness(tx) {
  let concstr = "";
  for (const vinEntry of tx.vin) {
    const witness = vinEntry.witness;
    if (witness) {
      // Check if witness is defined
      concstr += witness.length.toString(16).padStart(2, "0");
      for (const wit of witness) {
        concstr += (wit.length / 2).toString(16).padStart(2, "0") + wit;
      }
    }
  }
  return concstr;
}

  
