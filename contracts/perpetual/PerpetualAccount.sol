// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;
import "../token/IERC20.sol";

/// @title  The user withdrawal contract can be used to withdraw assets to the source account
contract PerpetualAccount {
    address public owner;
    receive() external payable {}


    constructor(address _owner) payable {
        owner = _owner;
    }

    /**
        @notice Used for user withdrawal. This method can transfer the specified token to the source account
        @param  tokenAddress token contract address
        @param  amount withdraw amount
    */
    function withdraw(address tokenAddress, uint256 amount) external  {
        if(tokenAddress == address(0)){
            safeTransferNativeToken(owner,amount);
        }else{
            releaseERC20(tokenAddress, owner, amount);
        }
    }

    /**
        @notice Transfers native of token to recipient.
        @param to Address to transfer tokens to.
        @param value Amount of tokens to transfer.
     */
    function safeTransferNativeToken(address to, uint value) internal {
        (bool success,) = to.call{value:value}(new bytes(0));
        require(success, 'TransferHelper: Native token transfer failed');
    }

    /**
        @notice Transfers custody of token to recipient.
        @param tokenAddress Address of ERC20 to transfer.
        @param recipient Address to transfer tokens to.
        @param amount Amount of tokens to transfer.
     */
    function releaseERC20(address tokenAddress, address recipient, uint256 amount) internal {
        IERC20 erc20 = IERC20(tokenAddress);
        _safeTransfer(erc20, recipient, amount);
    }

    /**
        @notice used to transfer ERC20s safely
        @param token Token instance to transfer
        @param to Address to transfer token to
        @param value Amount of token to transfer
     */
    function _safeTransfer(IERC20 token, address to, uint256 value) private {
        _safeCall(token, abi.encodeWithSelector(token.transfer.selector, to, value));
    }

    /**
        @notice used to make calls to ERC20s safely
        @param token Token instance call targets
        @param data encoded call data
     */
    function _safeCall(IERC20 token, bytes memory data) private {
        (bool success, bytes memory returndata) = address(token).call(data);
        require(success, "ERC20: call failed");

        if (returndata.length > 0) {
            require(abi.decode(returndata, (bool)), "ERC20: operation did not succeed");
        }
    }



}