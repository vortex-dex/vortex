// SPDX-License-Identifier: MIT OR Apache-2.0

pragma solidity ^0.7.0;

pragma experimental ABIEncoderV2;


import ".././security/ReentrancyGuard.sol";
import ".././utils/SafeMath.sol";
import ".././utils/SafeMathUInt128.sol";
import ".././utils/SafeCast.sol";
import ".././utils/Utils.sol";

import ".././library/Storage.sol";
import "./ActionConstants.sol";
import ".././library/Events.sol";

import ".././utils/Bytes.sol";
import ".././library/Operations.sol";

import ".././upgrade/UpgradeableMaster.sol";
import ".././library/RegenesisMultisig.sol";
import ".././AdditionalVengine.sol";

/// @title vengine base action contract
contract BaseAction is Storage, ActionConstants,Events, ReentrancyGuard{

    // Priority queue

    /// @notice Saves priority request in storage
    /// @dev Calculates expiration block for request, store this request and emit NewPriorityRequest event
    /// @param _opType Rollup operation type
    /// @param _pubData Operation pubdata
    function addPriorityRequest(Operations.OpType _opType, bytes memory _pubData) internal {
        // Expiration block is: current block number + priority expiration delta
        uint64 expirationBlock = uint64(block.number + PRIORITY_EXPIRATION);

        uint64 nextPriorityRequestId = firstPriorityRequestId + totalOpenPriorityRequests;

        bytes20 hashedPubData = Utils.hashBytesToBytes20(_pubData);

        priorityRequests[nextPriorityRequestId] = PriorityOperation({
        hashedPubData: hashedPubData,
        expirationBlock: expirationBlock,
        opType: _opType
        });

        emit NewPriorityRequest(msg.sender, nextPriorityRequestId, _opType, _pubData, uint256(expirationBlock));

        totalOpenPriorityRequests++;
    }


}
