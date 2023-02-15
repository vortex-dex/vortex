// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

import "./PerpetualAccount.sol";

/// perpetual factory
contract PerpetualFactory {

    event Deployed(address addr, bytes32 salt);



    // 1. Get bytecode of contract to be deployed
    // NOTE: _owner :Address of the target withdrawal user
    //
    function getBytecode(address _owner) public pure returns (bytes memory) {
        bytes memory bytecode = type(PerpetualAccount).creationCode;
        return abi.encodePacked(bytecode, abi.encode(_owner));
    }



    // 2. Deploy the contract
    // NOTE:
    // Check the event log Deployed which contains the address of the deployed PerpetualAccount.
    // The address in the log should equal the address computed from above.
    function deploy(bytes memory bytecode, bytes32 _salt) public payable {
        address addr;

        /*
        NOTE: How to call create2

        create2(v, p, n, s)
        create new contract with code at memory p to p + n
        and send v wei
        and return the new address
        where new address = first 20 bytes of keccak256(0xff + address(this) + s + keccak256(mem[pâ¦(p+n)))
              s = big-endian 256-bit value
        */
        assembly {
            addr := create2(
            callvalue(), // wei sent with current call
            // Actual code starts after skipping the first 32 bytes
            add(bytecode, 0x20),
            mload(bytecode), // Load the size of code contained in the first 32 bytes
            _salt // Salt from function arguments
            )

            if iszero(extcodesize(addr)) {
                revert(0, 0)
            }
        }

        emit Deployed(addr, _salt);
    }

    function getAddress(
        bytes memory bytecode,
        bytes32 _salt
    ) public view returns (address) {
        bytes32 hash = keccak256(
            abi.encodePacked(bytes1(0xff), address(this), _salt, keccak256(bytecode))
        );
        // NOTE: cast last 20 bytes of hash to address
        return address(uint160(uint256(hash)));
    }
}
