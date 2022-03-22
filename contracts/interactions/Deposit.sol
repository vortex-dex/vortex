// SPDX-License-Identifier: MIT OR Apache-2.0

pragma solidity ^0.7.0;

pragma experimental ABIEncoderV2;

import "./BaseAction.sol";

/// @title vengine deposit contract
contract Deposit is BaseAction{

    using SafeMath for uint256;
    using SafeMathUInt128 for uint128;

    /// @notice Deposit ETH to Layer 2 - transfer ether from user into contract, validate it, register deposit
    /// @param _vengineAddress The receiver Layer 2 address
    function depositNativeToken(address _vengineAddress) external payable {
        require(_vengineAddress != SPECIAL_ACCOUNT_ADDRESS, "3d");
        requireActive();
        registerDeposit(0, SafeCast.toUint128(msg.value), _vengineAddress);
    }

    /// @notice Deposit ERC20 token to Layer 2 - transfer ERC20 tokens from user into contract, validate it, register deposit
    /// @param _token Token address
    /// @param _amount Token amount
    /// @param _vengineAddress Receiver Layer 2 address
    function depositERC20(
        IERC20 _token,
        uint104 _amount,
        address _vengineAddress
    ) external nonReentrant {
        require(_vengineAddress != SPECIAL_ACCOUNT_ADDRESS, "3d");
        requireActive();

        // Get token id by its address
        uint16 tokenId = governance.validateTokenAddress(address(_token));
        require(!governance.pausedTokens(tokenId), "3e"); // token deposits are paused

        uint256 balanceBefore = _token.balanceOf(address(this));
        require(Utils.transferFromERC20(_token, msg.sender, address(this), SafeCast.toUint128(_amount)), "3f"); // token transfer failed deposit
        uint256 balanceAfter = _token.balanceOf(address(this));
        uint128 depositAmount = SafeCast.toUint128(balanceAfter.sub(balanceBefore));
        require(depositAmount <= MAX_DEPOSIT_AMOUNT, "3g");

        registerDeposit(tokenId, depositAmount, _vengineAddress);
    }


    /// @notice Register deposit request - pack pubdata, add priority request and emit OnchainDeposit event
    /// @param _tokenId Token by id
    /// @param _amount Token amount
    /// @param _owner Receiver
    function registerDeposit(
        uint16 _tokenId,
        uint128 _amount,
        address _owner
    ) internal {
        // Priority Queue request
        Operations.Deposit memory op = Operations.Deposit({
        accountId: 0, // unknown at this point
        owner: _owner,
        tokenId: _tokenId,
        amount: _amount
        });
        bytes memory pubData = Operations.writeDepositPubdataForPriorityQueue(op);
        addPriorityRequest(Operations.OpType.Deposit, pubData);
        emit Deposit(_tokenId, _amount);
    }

}
