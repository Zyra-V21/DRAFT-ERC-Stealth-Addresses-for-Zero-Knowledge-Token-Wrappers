// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title IzkWrapper0zk
 * @notice Interface for zkWrapper0zk - ERC-8065 Extension with Stealth Addresses
 * @dev Compatible with ERC-8065 base interface, adds 0zk address support
 * 
 * Key Difference from IzkWrapper:
 * - Deposit TO a 0zk address (receiver's masterPublicKey derived)
 * - ciphertext + ephemeralPubKey enable receiver scanning via ECDH
 * - Only owner of nullifyingKey can spend notes
 * - No need to share secrets - just share 0zk address
 * 
 * Commitment scheme is implementation-defined. Example:
 * - notePublicKey = Poseidon(receiverMasterPublicKey, random)
 * - commitment = Poseidon(notePublicKey, tokenHash, amount, assetId)
 * - nullifierHash = Poseidon(nullifyingKey, leafIndex)
 */
interface IzkWrapper0zk {
    // ============ EVENTS ============
    
    event AssetRegistered(uint256 indexed assetId, address indexed token);
    
    /// @notice Emitted when tokens are deposited to a stealth address
    /// @param commitment The note commitment inserted into Merkle tree
    /// @param recipientIndex keccak256(recipientMasterPubKey)[:20] for event filtering
    /// @param leafIndex Index in the Merkle tree
    /// @param assetId Asset identifier
    /// @param timestamp Block timestamp
    /// @param ciphertext Encrypted note data for receiver to scan
    /// @param ephemeralPubKey Sender's ephemeral public key for ECDH
    event Deposit(
        bytes32 indexed commitment,
        address indexed recipientIndex,
        uint32 leafIndex,
        uint256 indexed assetId,
        uint256 timestamp,
        bytes ciphertext,
        bytes32 ephemeralPubKey
    );
    
    /// @notice Emitted when a private transfer occurs (extends ERC-8065 base event)
    /// @param nullifierHash Nullifier marking input as spent
    /// @param newCommitment New commitment for recipient
    /// @param assetId Asset being transferred
    /// @param newLeafIndex Index of new commitment
    /// @param recipientIndex keccak256(newRecipientMasterPubKey)[:20] for event filtering
    /// @param ciphertext Encrypted note data for new receiver
    /// @param ephemeralPubKey Sender's ephemeral public key for ECDH
    event PrivateTransfer(
        bytes32 indexed nullifierHash,
        bytes32 indexed newCommitment,
        uint256 indexed assetId,
        uint32 newLeafIndex,
        address recipientIndex,
        bytes ciphertext,
        bytes32 ephemeralPubKey
    );
    
    /// @notice Emitted when a note is withdrawn
    /// @param nullifierHash Nullifier marking note as spent
    /// @param recipient Address receiving tokens
    /// @param assetId Asset being withdrawn
    event Withdraw(
        bytes32 indexed nullifierHash,
        address indexed recipient,
        uint256 indexed assetId
    );

    // ============ ERRORS ============
    
    error ZeroAmount();
    error InvalidDenomination(uint256 amount);
    error NullifierAlreadyUsed(bytes32 nullifier);
    error UnknownMerkleRoot(bytes32 root);
    error InvalidProof();
    error InvalidRecipient();
    error AssetNotRegistered(uint256 assetId);
    error AssetAlreadyRegistered(uint256 assetId);
    error TransferFailed();
    error InsufficientETH();

    // ============ DEPOSIT (ERC-8065 Compatible) ============
    
    /**
     * @notice Deposit tokens to a 0zk stealth address
     * @dev Locks tokens and creates commitment in ONE transaction.
     *      Includes encrypted note data for receiver scanning.
     * 
     * @param to Recipient identifier (can be commitment[:20] or pubKeyHash[:20])
     * @param id Asset identifier (0 for ETH, token address cast for ERC20)
     * @param amount Amount to deposit
     * @param data Encoded deposit data: abi.encode(commitment, ciphertext, ephemeralPubKey, proof)
     *             - commitment: bytes32 - The note commitment
     *             - ciphertext: bytes - Encrypted note data for receiver
     *             - ephemeralPubKey: bytes32 - Sender's ephemeral key for ECDH
     *             - proof: bytes - ZK proof of commitment knowledge
     */
    function deposit(
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) external payable;

    // ============ PRIVATE TRANSFER (ERC-8065 Compatible) ============
    
    /**
     * @notice Transfer between stealth addresses
     * @dev Extends base ERC-8065 privateTransfer with stealth data
     * @param proof ZK proof of ownership via nullifyingKey
     * @param nullifierHash Hash preventing double-spend
     * @param newCommitment New note commitment for recipient
     * @param root Merkle root for verification
     * @param assetId Asset being transferred
     * @param data Encoded stealth data: abi.encode(recipientIndex, ciphertext, ephemeralPubKey)
     *             - recipientIndex: address - keccak256(newRecipientMasterPubKey)[:20]
     *             - ciphertext: bytes - Encrypted note data for receiver scanning
     *             - ephemeralPubKey: bytes32 - Sender's ephemeral public key for ECDH
     */
    function privateTransfer(
        bytes calldata proof,
        bytes32 nullifierHash,
        bytes32 newCommitment,
        bytes32 root,
        uint256 assetId,
        bytes calldata data
    ) external;

    // ============ WITHDRAW (ERC-8065 Compatible) ============
    
    /**
     * @notice Withdraw from 0zk commitment to public address
     * @dev Burns the note and transfers tokens in ONE transaction
     * 
     * @param to Recipient address to receive tokens
     * @param id Asset identifier
     * @param amount Amount to withdraw
     * @param data Encoded withdraw data: abi.encode(root, nullifierHash, proof)
     */
    function withdraw(
        address to,
        uint256 id,
        uint256 amount,
        bytes calldata data
    ) external;

    // ============ VIEW FUNCTIONS ============
    
    function isKnownRoot(bytes32 root) external view returns (bool);
    function getLastRoot() external view returns (bytes32);
    function isNullifierUsed(bytes32 nullifier) external view returns (bool);
    function isAssetRegistered(uint256 assetId) external view returns (bool);
    function totalNotesCreated() external view returns (uint64);
    function getAssetBalance(uint256 assetId) external view returns (uint256);
    function ETH_ASSET_ID() external view returns (uint256);
}
