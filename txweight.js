function calculateTransactionWeight(tx) {
  let non_witness_bytes = 0;
  let witness_bytes = 0;

  let tx_type = tx["vin"].every((vin) => "scriptsig" in vin)
    ? "LEGACY"
    : "SEGWIT";

  if (tx_type === "LEGACY") {
    // VERSION
    non_witness_bytes += 4;

    if (tx["vin"].length >= 50) {
      throw new Error("Too many inputs");
    }

    // INPUT COUNT
    non_witness_bytes += 1;

    // INPUTS
    for (let input of tx["vin"]) {
      // TXID
      non_witness_bytes += 32;

      // VOUT
      non_witness_bytes += 4;

      // SCRIPTSIG
      let script_sig = Buffer.from(input["scriptsig"] || "", "hex");
      non_witness_bytes += 1 + script_sig.length;

      // SEQUENCE
      non_witness_bytes += 4;
    }

    if (tx["vout"].length >= 50) {
      throw new Error("Too many outputs");
    }

    // OUTPUT COUNT
    non_witness_bytes += 1;

    // OUTPUTS
    for (let output of tx["vout"]) {
      // VALUE
      non_witness_bytes += 8;

      // SCRIPTPUBKEY
      let scriptpubkey = Buffer.from(output["scriptpubkey"], "hex");
      non_witness_bytes += 1 + scriptpubkey.length;
    }

    // LOCKTIME
    non_witness_bytes += 4;
  } else {
    // VERSION
    non_witness_bytes += 4;

    // MARKER and FLAG (witness data)
    witness_bytes += 2;

    if (tx["vin"].length >= 50) {
      throw new Error("Too many inputs");
    }

    // INPUT COUNT
    non_witness_bytes += 1;

    // INPUTS
    for (let input of tx["vin"]) {
      // TXID and VOUT
      non_witness_bytes += 32 + 4;

      // SCRIPTSIG (if any)
      let script_sig = Buffer.from(input["scriptsig"] || "", "hex");
      non_witness_bytes += 1 + script_sig.length;

      // SEQUENCE
      non_witness_bytes += 4;
    }

    if (tx["vout"].length >= 255) {
      throw new Error("Too many outputs");
    }

    // OUTPUT COUNT
    non_witness_bytes += 1;

    // OUTPUTS
    for (let output of tx["vout"]) {
      // VALUE and SCRIPTPUBKEY
      let scriptpubkey = Buffer.from(output["scriptpubkey"], "hex");
      non_witness_bytes += 8 + 1 + scriptpubkey.length;
    }

    // WITNESS DATA
    for (let input of tx["vin"]) {
      let witness = input["witness"] || [];
      for (let item of witness) {
        let item_bytes = Buffer.from(item, "hex");
        witness_bytes += 1 + item_bytes.length;
      }
    }

    // LOCKTIME
    non_witness_bytes += 4;
  }

  // Calculate the total weight of the transaction
  let tx_weight = non_witness_bytes * 4 + witness_bytes;

  return tx_weight;
}

const tx = {
  version: 2,
  locktime: 834617,
  vin: [
    {
      txid: "055fcb804abceb297982920a9657efcb73c9e063d6b4716d208942917e3452b9",
      vout: 1,
      prevout: {
        scriptpubkey: "0014a3c3b81cf5767154da35b0e91a1ae8a6934857d4",
        scriptpubkey_asm:
          "OP_0 OP_PUSHBYTES_20 a3c3b81cf5767154da35b0e91a1ae8a6934857d4",
        scriptpubkey_type: "v0_p2wpkh",
        scriptpubkey_address: "bc1q50pms884wec4fk34kr535xhg56f5s475tpaqha",
        value: 4360000,
      },
      scriptsig: "",
      scriptsig_asm: "",
      witness: [
        "30440220364b1ef5c5eb33e148c7dfad232a35f0a7832a91b8897b0cc562997d6232353d02200ff0ffd239ccef87319ae07ab68d46679d0bd15208a304cc6c38a905401b2ac401",
        "0215b9092f84a792c90ddde532f7e574f9c5130c1552c2f41f724449beae1ccc3a",
      ],
      is_coinbase: false,
      sequence: 4294967293,
    },
    {
      txid: "e6914677cab32161c5109c402999881490dbec6abcb4007fbb762de711e71b41",
      vout: 0,
      prevout: {
        scriptpubkey: "0014a3c3b81cf5767154da35b0e91a1ae8a6934857d4",
        scriptpubkey_asm:
          "OP_0 OP_PUSHBYTES_20 a3c3b81cf5767154da35b0e91a1ae8a6934857d4",
        scriptpubkey_type: "v0_p2wpkh",
        scriptpubkey_address: "bc1q50pms884wec4fk34kr535xhg56f5s475tpaqha",
        value: 99960000,
      },
      scriptsig: "",
      scriptsig_asm: "",
      witness: [
        "304402203adf81697ad98e38b6c1d8fcf53bdbf657ec619e10fd00bb5f0f07f90e669ebc02202acf894513e3cfa05e32f46f9c9ab5548a8da6023c59241b780b9255b2b25c0901",
        "0215b9092f84a792c90ddde532f7e574f9c5130c1552c2f41f724449beae1ccc3a",
      ],
      is_coinbase: false,
      sequence: 4294967293,
    },
  ],
  vout: [
    {
      scriptpubkey: "a914f8f5620b60e9de36c1e504158cd9b11f7cc3b27787",
      scriptpubkey_asm:
        "OP_HASH160 OP_PUSHBYTES_20 f8f5620b60e9de36c1e504158cd9b11f7cc3b277 OP_EQUAL",
      scriptpubkey_type: "p2sh",
      scriptpubkey_address: "3QPPTdHhoQNV5MQffau83MmptQ7uzG6Utb",
      value: 50000000,
    },
    {
      scriptpubkey: "00141b97543b8cd70fa192633378c8c55e89fdaa1da9",
      scriptpubkey_asm:
        "OP_0 OP_PUSHBYTES_20 1b97543b8cd70fa192633378c8c55e89fdaa1da9",
      scriptpubkey_type: "v0_p2wpkh",
      scriptpubkey_address: "bc1qrwt4gwuv6u86rynrxduv3327387658dfnhmaqx",
      value: 54311400,
    },
  ],
};

console.log(calculateTransactionWeight(tx)); // 1244
