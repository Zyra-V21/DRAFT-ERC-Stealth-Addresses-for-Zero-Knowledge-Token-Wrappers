# Stealth Addresses for Zero Knowledge Token Wrappers

Reference implementation for ERC-8065 Stealth Addresses extension.

## Specification

See [erc-draft-stealth-addresses-8065.md](./erc-draft-stealth-addresses-8065.md)

## Contracts

- `src/zkWrapper0zk.sol` - Main stealth address wrapper contract
- `src/interfaces/IzkWrapper0zk.sol` - Interface specification  
- `src/interfaces/IVerifier0zk.sol` - ZK proof verifier interfaces
- `src/components/` - Merkle tree and rate limiter components
- `src/libraries/` - Denomination library

## Dependencies

Requires OpenZeppelin Contracts v5:
- `@openzeppelin/contracts/token/ERC20/IERC20.sol`
- `@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol`
- `@openzeppelin/contracts/utils/ReentrancyGuard.sol`
- `@openzeppelin/contracts/utils/Pausable.sol`
- `@openzeppelin/contracts/access/Ownable.sol`
