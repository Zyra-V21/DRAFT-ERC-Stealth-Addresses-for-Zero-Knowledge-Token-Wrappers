// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title Verifier Interfaces for Stealth Address Circuits
 * @notice Interfaces for ZK proof verifiers generated from stealth address circom circuits
 * @dev These verifiers use the stealth address commitment scheme:
 *      - notePublicKey = Poseidon(receiverMasterPublicKey, random)
 *      - commitment = Poseidon(notePublicKey, tokenHash, amount, assetId)
 *      - nullifierHash = Poseidon(nullifyingKey, leafIndex)
 */

/**
 * @notice Deposit verifier for stealth addresses
 * @dev Public inputs: [amount, assetId, commitment]
 */
interface IDepositVerifier0zk {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[3] calldata _pubSignals
    ) external view returns (bool);
}

/**
 * @notice Transfer verifier for stealth addresses
 * @dev Public inputs: [root, nullifierHash, newCommitment, assetId]
 */
interface ITransferVerifier0zk {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[4] calldata _pubSignals
    ) external view returns (bool);
}

/**
 * @notice Withdraw verifier for stealth addresses
 * @dev Public inputs: [root, nullifierHash, amount, assetId, recipient]
 */
interface IWithdrawVerifier0zk {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[5] calldata _pubSignals
    ) external view returns (bool);
}

// Legacy aliases for backwards compatibility
interface IShieldVerifier0zk is IDepositVerifier0zk {}
interface IUnshieldVerifier0zk is IWithdrawVerifier0zk {}

