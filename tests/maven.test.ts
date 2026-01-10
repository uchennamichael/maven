import { afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { Cl, ClarityType } from "@stacks/transactions";
import { Buffer } from "buffer";
import { tx } from "@hirosystems/clarinet-sdk";
import { ec as EC } from "elliptic";
import { getPublicKey } from "@noble/secp256k1";

const accounts = simnet.getAccounts();
if (!accounts.size) {
  throw new Error("simnet has no wallets configured");
}

const ownerAddress = (() => {
  const address = accounts.get("wallet_1");
  if (!address) {
    throw new Error("wallet_1 missing from simnet");
  }
  return address;
})();

const oracleAddress = (() => {
  const address = accounts.get("wallet_2");
  if (!address) {
    throw new Error("wallet_2 missing from simnet");
  }
  return address;
})();

let contractOwner: string;

beforeAll(() => {
  const ownerCv = simnet
    .callReadOnlyFn(contractName, "get-contract-owner", [], ownerAddress)
    .result;
  if (!ownerCv || typeof ownerCv !== "object") {
    throw new Error("unexpected contract owner result");
  }
  const ownerValue = (ownerCv as { value?: any }).value;
  if (typeof ownerValue === "string") {
    contractOwner = ownerValue;
  } else if (ownerValue && typeof ownerValue.address === "string") {
    contractOwner = ownerValue.address;
  } else {
    throw new Error("unable to derive contract owner principal");
  }
});

const contractName = "maven";
const oracleMap = "oracles";
const MIN_BLOCK_INTERVAL = 10n;
const elliptic = new EC("secp256k1");

const signerPrivateKey = hexToBytes("0101010101010101010101010101010101010101010101010101010101010101");
const signerPubkey = Buffer.from(getPublicKey(signerPrivateKey, true));
const alternatePrivateKey = hexToBytes("0202020202020202020202020202020202020202020202020202020202020202");
const alternatePubkey = Buffer.from(getPublicKey(alternatePrivateKey, true));

beforeEach(async () => {
  await ensureOracleRemoved();
});

afterEach(async () => {
  await ensureOracleRemoved();
});

describe("maven Oracle contract", () => {
  it("registers a fresh oracle entry", async () => {
    const registerReceipt = await registerOracle(signerPubkey);
    expect(registerReceipt.result).toBeOk(Cl.bool(true));

    const oracleData = simnet
      .callReadOnlyFn(
        contractName,
        "get-oracle-data",
        [Cl.standardPrincipal(oracleAddress)],
        ownerAddress,
      )
      .result;
    expect(oracleData.type).toBe(ClarityType.OptionalSome);
  });

  it("accepts signed proofs and refreshes helpers", async () => {
    await registerOracle(signerPubkey);
    const value = createValue(1);
    const nonce = 1n;
    const receipt = await submitProof(
      oracleAddress,
      value,
      nonce,
      signProof(oracleAddress, value, nonce),
    );
    expect(receipt.result).toBeOk(Cl.bool(true));

    const updates = simnet
      .callReadOnlyFn(contractName, "get-oracle-updates-count", [], ownerAddress)
      .result;
    expect(updates).toBeUint(1);

    const fresh = simnet
      .callReadOnlyFn(
        contractName,
        "is-oracle-fresh",
        [Cl.standardPrincipal(oracleAddress), Cl.uint(5)],
        ownerAddress,
      )
      .result;
    expect(fresh).toBeBool(true);

    const latestValue = simnet
      .callReadOnlyFn(
        contractName,
        "get-latest-value-if-fresh",
        [Cl.standardPrincipal(oracleAddress)],
        ownerAddress,
      )
      .result;
    expect(latestValue.type).toBe(ClarityType.OptionalSome);
  });

  it("rejects proofs whose nonce does not increase by one", async () => {
    await registerOracle(signerPubkey);
    await submitProof(
      oracleAddress,
      createValue(2),
      1n,
      signProof(oracleAddress, createValue(2), 1n),
    );

    await simnet.mineEmptyBlocks(Number(MIN_BLOCK_INTERVAL));

    const replayReceipt = await submitProof(
      oracleAddress,
      createValue(3),
      1n,
      signProof(oracleAddress, createValue(3), 1n),
    );
    expect(replayReceipt.result).toBeErr(Cl.uint(105));
  });

  it("enforces the minimum block interval between updates", async () => {
    await registerOracle(signerPubkey);
    await submitProof(
      oracleAddress,
      createValue(4),
      1n,
      signProof(oracleAddress, createValue(4), 1n),
    );

    await simnet.mineEmptyBlocks(1);

    const rateLimitReceipt = await submitProof(
      oracleAddress,
      createValue(5),
      2n,
      signProof(oracleAddress, createValue(5), 2n),
    );
    expect(rateLimitReceipt.result).toBeErr(Cl.uint(103));
  });

  it("rejects invalid signatures even when nonce is correct", async () => {
    await registerOracle(signerPubkey);

    const badSignature = Buffer.alloc(65, 0);
    const receipt = await submitProof(
      oracleAddress,
      createValue(6),
      1n,
      badSignature,
    );
    expect(receipt.result).toBeErr(Cl.uint(102));
  });

  it("lets the owner pause updates while rejecting proofs", async () => {
    await registerOracle(signerPubkey);
    await submitProof(
      oracleAddress,
      createValue(7),
      1n,
      signProof(oracleAddress, createValue(7), 1n),
    );

    const pauseTx = tx.callPublicFn(
      contractName,
      "set-oracle-active",
      [Cl.standardPrincipal(oracleAddress), Cl.bool(false)],
      contractOwner,
    );
    const [pauseReceipt] = await simnet.mineBlock([pauseTx]);
    expect(pauseReceipt.result).toBeOk(Cl.bool(true));

    const blockedReceipt = await submitProof(
      oracleAddress,
      createValue(8),
      2n,
      signProof(oracleAddress, createValue(8), 2n),
    );
    expect(blockedReceipt.result).toBeErr(Cl.uint(106));
  });

  it("allows the owner to rotate the signer and keep history", async () => {
    await registerOracle(signerPubkey);
    await submitProof(
      oracleAddress,
      createValue(9),
      1n,
      signProof(oracleAddress, createValue(9), 1n),
    );

    const rotateTx = tx.callPublicFn(
      contractName,
      "update-oracle-signer",
      [Cl.standardPrincipal(oracleAddress), Cl.buffer(alternatePubkey)],
      contractOwner,
    );
    const [rotateReceipt] = await simnet.mineBlock([rotateTx]);
    expect(rotateReceipt.result).toBeOk(Cl.bool(true));

    await simnet.mineEmptyBlocks(Number(MIN_BLOCK_INTERVAL));

    const proofAfterRotate = await submitProof(
      oracleAddress,
      createValue(10),
      2n,
      signProof(oracleAddress, createValue(10), 2n, alternatePrivateKey),
    );
    expect(proofAfterRotate.result).toBeOk(Cl.bool(true));
  });
});

async function registerOracle(signer: Buffer) {
  const call = tx.callPublicFn(
    contractName,
    "register-oracle",
    [Cl.buffer(signer)],
    oracleAddress,
  );
  return (await simnet.mineBlock([call]))[0];
}

async function submitProof(
  user: string,
  value: Buffer,
  nonce: bigint,
  signature: Buffer,
  sender: string = ownerAddress,
) {
  const call = tx.callPublicFn(
    contractName,
    "submit-proof",
    [Cl.standardPrincipal(user), Cl.buffer(value), Cl.buffer(signature), Cl.uint(nonce)],
    sender,
  );
  return (await simnet.mineBlock([call]))[0];
}

async function ensureOracleRemoved() {
  let entry;
  try {
    entry = simnet.getMapEntry(
      contractName,
      oracleMap,
      Cl.standardPrincipal(oracleAddress),
    );
  } catch (error) {
    if (
      error === "value not found" ||
      (error instanceof Error && error.message === "value not found")
    ) {
      return;
    }
    throw error;
  }

  if (entry?.type !== ClarityType.OptionalSome) {
    return;
  }

  const removeTx = tx.callPublicFn(
    contractName,
    "remove-oracle",
    [Cl.standardPrincipal(oracleAddress)],
    contractOwner,
  );
  const [receipt] = await simnet.mineBlock([removeTx]);
  expect(receipt.result).toBeOk(Cl.bool(true));
}

function createValue(seed: number) {
  const value = Buffer.alloc(32, 0);
  value.fill(seed & 0xff);
  value.writeUInt32BE(seed, 28);
  return value;
}

function signProof(
  user: string,
  value: Buffer,
  nonce: bigint,
  privateKey: Uint8Array = signerPrivateKey,
) {
  if (value.length !== 32) {
    throw new Error("oracle value must be 32 bytes");
  }

  const hash = getProofMessageHash(user, value, nonce);
  const key = elliptic.keyFromPrivate(Buffer.from(privateKey));
  const signature = key.sign(hash, { canonical: true });
  const r = signature.r.toArrayLike(Buffer, "be", 32);
  const s = signature.s.toArrayLike(Buffer, "be", 32);
  const recovery = signature.recoveryParam ?? 0;

  const result = new Uint8Array(65);
  result.set(r, 0);
  result.set(s, 32);
  result[64] = recovery;

  return Buffer.from(result);
}

function getProofMessageHash(user: string, value: Buffer, nonce: bigint) {
  const hashResult = simnet
    .callReadOnlyFn(
      contractName,
      "get-proof-message-hash",
      [Cl.standardPrincipal(user), Cl.buffer(value), Cl.uint(nonce)],
      ownerAddress,
    )
    .result;

  if (hashResult.type !== ClarityType.Buffer) {
    throw new Error("proof hash result was not a buffer");
  }

  return bufferFromHex(hashResult.value);
}

function hexToBytes(value: string) {
  return Uint8Array.from(Buffer.from(value, "hex"));
}

function bufferFromHex(value: string) {
  const trimmed = value.startsWith("0x") ? value.slice(2) : value;
  return Buffer.from(trimmed, "hex");
}
