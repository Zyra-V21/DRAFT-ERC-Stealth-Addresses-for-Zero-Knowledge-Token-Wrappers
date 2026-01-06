// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

import {IDepositVerifier0zk, ITransferVerifier0zk, IWithdrawVerifier0zk} from "./interfaces/IVerifier0zk.sol";
import "./interfaces/IzkWrapper0zk.sol";
import "./components/MerkleTreeComponent.sol";
import "./components/RateLimiterComponent.sol";
import "./libraries/DenominationLib.sol";

/**
 * @title zkWrapper0zk
 * @author Ceaser Protocol
 * @notice ERC-8065 Extension: Stealth Addresses for multi-asset privacy
 * @dev Separate pool from zkWrapper with stealth address support.
 *      Uses ERC-8065 compatible interface with generic deposit/withdraw functions.
 *      Receivers can scan for notes using their viewing key without sharing secrets.
 *      
 *      Commitment scheme (implementation-defined):
 *      - notePublicKey = Poseidon(receiverMasterPublicKey, random)
 *      - commitment = Poseidon(notePublicKey, tokenHash, amount, assetId)
 *      - nullifierHash = Poseidon(nullifyingKey, leafIndex)
 *      - nullifyingKey = Poseidon(masterPrivateKey, viewingPrivateKey)
 */
contract zkWrapper0zk is 
    IzkWrapper0zk,
    MerkleTreeComponent,
    RateLimiterComponent,
    ReentrancyGuard,
    Pausable,
    Ownable 
{
    using SafeERC20 for IERC20;
    using DenominationLib for uint256;

    /// @notice Asset ID for native ETH
    uint256 public constant ETH_ASSET_ID = 0;

    /// @notice Verifier contracts (generated from circuits/stealth/)
    IDepositVerifier0zk public immutable depositVerifier;
    ITransferVerifier0zk public immutable transferVerifier;
    IWithdrawVerifier0zk public immutable withdrawVerifier;
    
    /// @notice Nullifiers (spent notes) - prevents double-spending
    mapping(bytes32 => bool) public nullifiers;
    
    /// @notice Registered assets (assetId => token address, 0x0 for ETH)
    mapping(uint256 => address) public registeredAssets;
    
    /// @notice Total locked per asset (for accounting)
    mapping(uint256 => uint256) public totalLocked;
    
    /// @notice Total notes created in this pool
    uint64 public totalNotesCreated;
    
    error ZeroAddress();
    error InvalidDataLength();

    constructor(
        address _depositVerifier,
        address _transferVerifier,
        address _withdrawVerifier,
        address _poseidon
    ) 
        MerkleTreeComponent(_poseidon)
        Ownable(msg.sender) 
    {
        if (_depositVerifier == address(0)) revert ZeroAddress();
        if (_transferVerifier == address(0)) revert ZeroAddress();
        if (_withdrawVerifier == address(0)) revert ZeroAddress();
        
        depositVerifier = IDepositVerifier0zk(_depositVerifier);
        transferVerifier = ITransferVerifier0zk(_transferVerifier);
        withdrawVerifier = IWithdrawVerifier0zk(_withdrawVerifier);
        
        registeredAssets[ETH_ASSET_ID] = address(0);
        emit AssetRegistered(ETH_ASSET_ID, address(0));
    }

    error InvalidTokenAddress();

    /**
     * @notice Register a new ERC20 token for privacy
     * @param token ERC20 token address
     * @return assetId The assigned asset ID
     */
    function registerAsset(address token) external onlyOwner returns (uint256 assetId) {
        if (token == address(0)) revert InvalidTokenAddress();
        
        assetId = uint256(uint160(token));
        
        if (registeredAssets[assetId] != address(0) && assetId != ETH_ASSET_ID) {
            revert AssetAlreadyRegistered(assetId);
        }
        
        registeredAssets[assetId] = token;
        emit AssetRegistered(assetId, token);
    }

    /**
     * @notice Deposit tokens to a stealth address (ERC-8065 compatible)
     * @param to Recipient index: address(bytes20(keccak256(recipientMasterPubKey)))
     *           Enables efficient event filtering for note scanning
     * @param id Asset identifier (0 for ETH, token address cast for ERC20)
     * @param amount Amount to deposit
     * @param data Encoded: abi.encode(commitment, ciphertext, ephemeralPubKey, proof)
     */
    function deposit(
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) external payable nonReentrant whenNotPaused {
        // Decode data
        (
            bytes32 commitment,
            bytes memory ciphertext,
            bytes32 ephemeralPubKey,
            bytes memory proof
        ) = abi.decode(data, (bytes32, bytes, bytes32, bytes));
        
        // Validate amount
        if (amount == 0) revert ZeroAmount();
        if (!DenominationLib.isValid(amount)) revert InvalidDenomination(amount);
        
        // Rate limiting
        _checkShieldLimit(amount);
        
        // Decode proof to uint256[8] for verifier
        uint256[8] memory proofArray = _decodeProof(proof);
        
        // Verify ZK proof (3 public inputs: amount, assetId, commitment)
        bool valid = depositVerifier.verifyProof(
            [proofArray[0], proofArray[1]],
            [[proofArray[2], proofArray[3]], [proofArray[4], proofArray[5]]],
            [proofArray[6], proofArray[7]],
            [amount, id, uint256(commitment)]
        );
        if (!valid) revert InvalidProof();
        
        // Handle asset transfer
        if (id == ETH_ASSET_ID) {
            // Native ETH
            if (msg.value != amount) revert InsufficientETH();
        } else {
            // ERC20
            address token = registeredAssets[id];
            if (token == address(0)) revert AssetNotRegistered(id);
            IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        }
        
        // Insert commitment into Merkle tree
        uint32 leafIndex = _insert(commitment);
        
        totalLocked[id] += amount;
        totalNotesCreated++;
        
        // 'to' is recipientIndex for efficient event filtering
        emit Deposit(commitment, to, leafIndex, id, block.timestamp, ciphertext, ephemeralPubKey);
    }
    
    /**
     * @notice Transfer private note to another stealth address (ERC-8065 compatible)
     * @param proof ZK proof of ownership via nullifyingKey
     * @param nullifierHash Hash preventing double-spend
     * @param newCommitment New note commitment for recipient
     * @param root Merkle root to verify against
     * @param assetId Asset being transferred
     * @param data Encoded stealth data: abi.encode(recipientIndex, ciphertext, ephemeralPubKey)
     */
    function privateTransfer(
        bytes calldata proof,
        bytes32 nullifierHash,
        bytes32 newCommitment,
        bytes32 root,
        uint256 assetId,
        bytes calldata data
    ) external nonReentrant whenNotPaused {
        if (!isKnownRoot(root)) revert UnknownMerkleRoot(root);
        if (nullifiers[nullifierHash]) revert NullifierAlreadyUsed(nullifierHash);
        
        // Decode stealth data
        (
            address recipientIndex,
            bytes memory ciphertext,
            bytes32 ephemeralPubKey
        ) = abi.decode(data, (address, bytes, bytes32));
        
        // Decode proof
        uint256[8] memory proofArray = _decodeProof(proof);
        
        bool valid = transferVerifier.verifyProof(
            [proofArray[0], proofArray[1]],
            [[proofArray[2], proofArray[3]], [proofArray[4], proofArray[5]]],
            [proofArray[6], proofArray[7]],
            [uint256(root), uint256(nullifierHash), uint256(newCommitment), assetId]
        );
        if (!valid) revert InvalidProof();
        
        nullifiers[nullifierHash] = true;
        uint32 newLeafIndex = _insert(newCommitment);
        totalNotesCreated++;
        
        emit PrivateTransfer(nullifierHash, newCommitment, assetId, newLeafIndex, recipientIndex, ciphertext, ephemeralPubKey);
    }
    
    /**
     * @notice Withdraw from stealth commitment to public address (ERC-8065 compatible)
     * @param to Recipient address to receive tokens
     * @param id Asset identifier
     * @param amount Amount to withdraw
     * @param data Encoded: abi.encode(root, nullifierHash, proof)
     */
    function withdraw(
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) external nonReentrant whenNotPaused {
        // Decode data
        (bytes32 root, bytes32 nullifierHash, bytes memory proof) = abi.decode(data, (bytes32, bytes32, bytes));
        
        // Validate
        if (!isKnownRoot(root)) revert UnknownMerkleRoot(root);
        if (nullifiers[nullifierHash]) revert NullifierAlreadyUsed(nullifierHash);
        if (!DenominationLib.isValid(amount)) revert InvalidDenomination(amount);
        if (to == address(0)) revert InvalidRecipient();
        
        _checkBurnLimit(amount);
        
        // Decode proof
        uint256[8] memory proofArray = _decodeProof(proof);
        
        bool valid = withdrawVerifier.verifyProof(
            [proofArray[0], proofArray[1]],
            [[proofArray[2], proofArray[3]], [proofArray[4], proofArray[5]]],
            [proofArray[6], proofArray[7]],
            [uint256(root), uint256(nullifierHash), amount, id, uint256(uint160(to))]
        );
        if (!valid) revert InvalidProof();
        
        nullifiers[nullifierHash] = true;
        totalLocked[id] -= amount;
        
        if (id == ETH_ASSET_ID) {
            (bool success, ) = to.call{value: amount}("");
            if (!success) revert TransferFailed();
        } else {
            address token = registeredAssets[id];
            if (token == address(0)) revert AssetNotRegistered(id);
            IERC20(token).safeTransfer(to, amount);
        }
        
        emit Withdraw(nullifierHash, to, id);
    }

    /**
     * @dev Decode bytes proof to uint256[8] array for Groth16 verifiers
     */
    function _decodeProof(bytes memory proof) internal pure returns (uint256[8] memory) {
        if (proof.length != 256) revert InvalidDataLength();
        
        uint256[8] memory proofArray;
        for (uint256 i = 0; i < 8; i++) {
            assembly {
                mstore(add(proofArray, mul(i, 32)), mload(add(add(proof, 32), mul(i, 32))))
            }
        }
        return proofArray;
    }

    function isKnownRoot(bytes32 root) public view override(IzkWrapper0zk, MerkleTreeComponent) returns (bool) {
        return MerkleTreeComponent.isKnownRoot(root);
    }
    
    function getLastRoot() external view override(IzkWrapper0zk, MerkleTreeComponent) returns (bytes32) {
        return roots[currentRootIndex];
    }
    
    function isNullifierUsed(bytes32 nullifier) external view returns (bool) {
        return nullifiers[nullifier];
    }
    
    function isAssetRegistered(uint256 assetId) external view returns (bool) {
        return assetId == ETH_ASSET_ID || registeredAssets[assetId] != address(0);
    }
    
    function getAssetBalance(uint256 assetId) external view returns (uint256) {
        return totalLocked[assetId];
    }

    function pause() external onlyOwner {
        _pause();
    }
    
    function unpause() external onlyOwner {
        _unpause();
    }

    error DirectETHNotAllowed();

    receive() external payable {
        revert DirectETHNotAllowed();
    }
}
