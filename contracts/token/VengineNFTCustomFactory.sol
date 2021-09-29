pragma solidity ^0.7.0;

import "./VengineNFTFactory.sol";
import ".././governance/Governance.sol";

contract VengineNFTCustomFactory is VengineNFTFactory {
    Governance internal governance;

    constructor(
        string memory name,
        string memory symbol,
        address vengineAddress,
        address governanceVengineAddress
    ) VengineNFTFactory(name, symbol, vengineAddress) {
        governance = Governance(governanceVengineAddress);
    }

    function registerNFTFactory(
        uint32 _creatorAccountId,
        address _creatorAddress,
        bytes memory _signature
    ) external {
        governance.registerNFTFactoryCreator(_creatorAccountId, _creatorAddress, _signature);
    }
}
