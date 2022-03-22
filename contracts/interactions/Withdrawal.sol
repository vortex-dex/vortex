// SPDX-License-Identifier: MIT OR Apache-2.0

pragma solidity ^0.7.0;

pragma experimental ABIEncoderV2;

import "./BaseAction.sol";

/// @title vengine wtihdrawal contract
contract Withdrawal is BaseAction{

    /// @notice Register full withdraw request - pack pubdata, add priority request
    /// @param _accountId Numerical id of the account
    /// @param _token Token address, 0 address for ether
    function requestFullWithdraw(uint32 _accountId, address _token) public nonReentrant {
        requireActive();
        require(_accountId <= MAX_ACCOUNT_ID, "3j");
        require(_accountId != SPECIAL_ACCOUNT_ID, "3k"); // request full withdraw for nft storage account

        uint16 tokenId;
        if (_token == address(0)) {
            tokenId = 0;
        } else {
            tokenId = governance.validateTokenAddress(_token);
        }

        // Priority Queue request
        Operations.FullWithdraw memory op = Operations.FullWithdraw({
        accountId: _accountId,
        owner: msg.sender,
        tokenId: tokenId,
        amount: 0, // unknown at this point
        nftCreatorAccountId: uint32(0), // unknown at this point
        nftCreatorAddress: address(0), // unknown at this point
        nftSerialId: uint32(0), // unknown at this point
        nftContentHash: bytes32(0) // unknown at this point
        });
        bytes memory pubData = Operations.writeFullWithdrawPubdataForPriorityQueue(op);
        addPriorityRequest(Operations.OpType.FullWithdraw, pubData);

        // User must fill storage slot of balancesToWithdraw(msg.sender, tokenId) with nonzero value
        // In this case operator should just overwrite this slot during confirming withdrawal
        bytes22 packedBalanceKey = packAddressAndTokenId(msg.sender, tokenId);
        pendingBalances[packedBalanceKey].gasReserveValue = FILLED_GAS_RESERVE_VALUE;
    }

    /// @notice Register full withdraw nft request - pack pubdata, add priority request
    /// @param _accountId Numerical id of the account
    /// @param _tokenId NFT token id in vengine network
    function requestFullWithdrawNFT(uint32 _accountId, uint32 _tokenId) public nonReentrant {
        requireActive();
        require(_accountId <= MAX_ACCOUNT_ID, "3l");
        require(_accountId != SPECIAL_ACCOUNT_ID, "3m"); // request full withdraw nft for nft storage account
        require(MAX_FUNGIBLE_TOKEN_ID < _tokenId && _tokenId < SPECIAL_NFT_TOKEN_ID, "3n"); // request full withdraw nft for invalid token id

        // Priority Queue request
        Operations.FullWithdraw memory op = Operations.FullWithdraw({
        accountId: _accountId,
        owner: msg.sender,
        tokenId: _tokenId,
        amount: 0, // unknown at this point
        nftCreatorAccountId: uint32(0), // unknown at this point
        nftCreatorAddress: address(0), // unknown at this point
        nftSerialId: uint32(0), // unknown at this point
        nftContentHash: bytes32(0) // unknown at this point
        });
        bytes memory pubData = Operations.writeFullWithdrawPubdataForPriorityQueue(op);
        addPriorityRequest(Operations.OpType.FullWithdraw, pubData);
    }

}
