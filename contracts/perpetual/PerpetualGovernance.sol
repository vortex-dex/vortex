// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

import "./../governance/Governance.sol";


// perpetual oracle
contract PerpetualGovernance {

    /// @notice vengine governance contract
    Governance public governance;

    /// @notice Provider's status changed
    event PriceProviderStatusUpdate(address indexed priceProviderAddress, bool isActive);

    /// @notice List of permitted priceProvider
    mapping(address => bool) public priceProviders;

    constructor(
            Governance _governance
    )  {
        governance = _governance;
    }


    /// @notice Change price provider status (active or not active)
    /// @param _priceProvider Price Provider address
    /// @param _active Active flag
    function setPriceProvider(address _priceProvider, bool _active) external {
        governance.requireGovernor(msg.sender);

    if (priceProviders[_priceProvider] != _active) {
        priceProviders[_priceProvider] = _active;
            emit PriceProviderStatusUpdate(_priceProvider, _active);
        }
    }

}
