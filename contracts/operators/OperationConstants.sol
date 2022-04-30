// SPDX-License-Identifier: MIT OR Apache-2.0

pragma solidity ^0.7.0;
import ".././library/Constants.sol";

/// @title vengine operation constants
contract OperationConstants is Constants{
    /// @dev ERC20 tokens and ETH withdrawals gas limit, used only for complete withdrawals
    uint256 internal constant WITHDRAWAL_GAS_LIMIT = 100000;

    /// @dev NFT withdrawals gas limit, used only for complete withdrawals
    uint256 internal constant WITHDRAWAL_NFT_GAS_LIMIT = 300000;

    /// @dev Bytes in one chunk
    uint8 internal constant CHUNK_BYTES = 10;

    uint256 internal constant NOOP_BYTES = 1 * CHUNK_BYTES;
    uint256 internal constant DEPOSIT_BYTES = 6 * CHUNK_BYTES;
    uint256 internal constant MINT_NFT_BYTES = 5 * CHUNK_BYTES;
    uint256 internal constant TRANSFER_TO_NEW_ADDR_BYTES = 6 * CHUNK_BYTES;
    uint256 internal constant PARTIAL_EXIT_BYTES = 6 * CHUNK_BYTES;
    uint256 internal constant TRANSFER_BYTES = 2 * CHUNK_BYTES;
    uint256 internal constant FORCED_WITHDRAW_BYTES = 6 * CHUNK_BYTES;
    uint256 internal constant WITHDRAW_NFT_BYTES = 10 * CHUNK_BYTES;
    uint256 internal constant PERPETUAL_SETTLEMENT_BYTES = 2 * CHUNK_BYTES;

    /// @dev Full withdraw operation length
    uint256 internal constant FULL_WITHDRAW_BYTES = 11 * CHUNK_BYTES;

    /// @dev UpdatePublicKey operation length
    uint256 internal constant UPDATE_PUBLIC_KEY_BYTES = 6 * CHUNK_BYTES;


    /// @dev Timestamp - seconds since unix epoch
    uint256 internal constant COMMIT_TIMESTAMP_NOT_OLDER = 168 hours;

    /// @dev Maximum available error between real commit block timestamp and analog used in the verifier (in seconds)
    /// @dev Must be used cause miner's `block.timestamp` value can differ on some small value (as we know - 15 seconds)
    uint256 internal constant COMMIT_TIMESTAMP_APPROXIMATION_DELTA = 15 minutes;

}
