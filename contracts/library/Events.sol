// SPDX-License-Identifier: MIT OR Apache-2.0

pragma solidity ^0.7.0;

import ".././upgrade/Upgradeable.sol";
import "./Operations.sol";

/// @title vengine events
interface Events {
    /// @notice Event emitted when a block is committed
    event BlockCommit(uint32 indexed blockNumber);

    /// @notice Event emitted when a block is verified
    event BlockVerification(uint32 indexed blockNumber);

    /// @notice Event emitted when user funds are withdrawn from the vengine state and contract
    event Withdrawal(uint16 indexed tokenId, uint128 amount);

    /// @notice Event emitted when user funds are withdrawn from the vengine state but not from contract
    event WithdrawalPending(uint16 indexed tokenId, uint128 amount);

    /// @notice Event emitted when user NFT is withdrawn from the vengine state and contract
    event WithdrawalNFT(uint32 indexed tokenId);

    /// @notice Event emitted when user NFT is withdrawn from the vengine state but not from contract
    event WithdrawalNFTPending(uint32 indexed tokenId);

    /// @notice Event emitted when user funds are deposited to the vengine contract
    event Deposit(uint16 indexed tokenId, uint128 amount);

    /// @notice Event emitted when user sends a authentication fact (e.g. pub-key hash)
    event FactAuth(address indexed sender, uint32 nonce, bytes fact);

    /// @notice Event emitted when blocks are reverted
    event BlocksRevert(uint32 totalBlocksVerified, uint32 totalBlocksCommitted);

    /// @notice SafeExit mode entered event
    event SafeExitMode();

    /// @notice New priority request event. Emitted when a request is placed into mapping
    event NewPriorityRequest(
        address sender,
        uint64 serialId,
        Operations.OpType opType,
        bytes pubData,
        uint256 expirationBlock
    );

    /// @notice Deposit committed event.
    event DepositCommit(
        uint32 indexed vengineBlockId,
        uint32 indexed accountId,
        address owner,
        uint16 indexed tokenId,
        uint128 amount
    );

    /// @notice Full withdraw committed event.
    event FullWithdrawCommit(
        uint32 indexed vengineBlockId,
        uint32 indexed accountId,
        address owner,
        uint16 indexed tokenId,
        uint128 amount
    );

    /// @notice Notice period changed
    event NoticePeriodChange(uint256 newNoticePeriod);
}