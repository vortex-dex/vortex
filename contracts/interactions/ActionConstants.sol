// SPDX-License-Identifier: MIT OR Apache-2.0

pragma solidity ^0.7.0;
import ".././library/Constants.sol";

/// @title vengine interaction constants
contract ActionConstants is Constants{

    /// @dev Max deposit of ERC20 token that is possible to deposit
    uint128 internal constant MAX_DEPOSIT_AMOUNT = $$((2**104) - 1);

    address internal constant SPECIAL_ACCOUNT_ADDRESS = address(0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF);

}
