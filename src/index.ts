import { Wallet } from "xrpl";
import { privateToAddress, privateToPublic } from "ethereumjs-util";

type Mapped_Keys = {
  xrpl_address: string;
  xrpl_secret: string;
  mapped_evm_private_key: string;
  mapped_evm_public_key: string;
  mapped_evm_public_address: string;
};

/// @notice Takes an xrpl secret and returns an object with both xrpl and ethereum key pairs
/// @param {string} xrplSecretKey - xrpl secret key
/// @returns {object} - object with both the xrpl and mapped EVM keypairs
export function mapXrplSecretToEvm(xrpl_secret_key: string): Mapped_Keys {
  // Get the XRPL keypair from the secret
  const xrpl_wallet = Wallet.fromSeed(xrpl_secret_key);

  // Convert the XRPL secret to hex
  const secretKeyToHex = Buffer.from(xrpl_secret_key, "utf8").toString("hex");

  // Ethereum private keys are 64 characters long when represented in hex
  // After converting our XRPL secret to hex, we need to pad it with 0s to make it 64 characters
  const padded_secret_key = secretKeyToHex.padStart(64, "0");

  // Convert the padded XRPL secret to a buffer
  // This is the private key we will use to sign transactions on the EVM
  const mapped_private_key = Buffer.from(padded_secret_key, "hex");

  // Get the evm public key and public address from the mapped private key
  const public_key = privateToPublic(mapped_private_key).toString("hex");
  const public_address = privateToAddress(mapped_private_key).toString("hex");

  const mapped_wallet: Mapped_Keys = {
    xrpl_address: `${xrpl_wallet.address}`,
    xrpl_secret: `${xrpl_wallet.seed}`,
    mapped_evm_private_key: mapped_private_key.toString("hex"),
    mapped_evm_public_key: `${public_key}`,
    mapped_evm_public_address: `0x${public_address}`,
  };

  return mapped_wallet;
}
