// SPDX-License-Identifier: MIT OR Apache-2.0

pragma solidity ^0.7.0;

pragma experimental ABIEncoderV2;

import "./security/ReentrancyGuard.sol";
import "./utils/SafeMath.sol";
import "./utils/SafeMathUInt128.sol";
import "./utils/SafeCast.sol";
import "./utils/Utils.sol";

import "./library/Storage.sol";
import "./library/Constants.sol";
import "./library/Events.sol";

import "./utils/Bytes.sol";
import "./library/Operations.sol";

import "./upgrade/Upgrade.sol";
import "./library/RegenesisMultisig.sol";
import "./AdditionalVengine.sol";

import "./interactions/Deposit.sol";
import "./interactions/Withdrawal.sol";
import "./operators/BlockOperator.sol";

/// @title vengine main contract
contract Vengine is Upgrade,BlockOperator,Deposit,Withdrawal {
    using SafeMath for uint256;
    using SafeMathUInt128 for uint128;

    /// @notice vengine contract upgrade. Can be external because Proxy contract intercepts illegal calls of this function.
    /// @param upgradeParameters Encoded representation of upgrade parameters
    // solhint-disable-next-line no-empty-blocks
    function upgrade(bytes calldata upgradeParameters) external nonReentrant {
        approvedUpgradeNoticePeriod = UPGRADE_NOTICE_PERIOD;
        additionalVengine = AdditionalVengine($(NEW_ADDITIONAL_VENGINE_ADDRESS));
    }

    constructor() {
        initializeReentrancyGuard();
    }

    /// @notice vengine contract initialization. Can be external because Proxy contract intercepts illegal calls of this function.
    /// @param initializationParameters Encoded representation of initialization parameters:
    /// @dev _governanceAddress The address of Governance contract
    /// @dev _verifierAddress The address of Verifier contract
    /// @dev _genesisStateHash Genesis blocks (first block) state tree root hash
    function initialize(bytes calldata initializationParameters) external {
        initializeReentrancyGuard();

        (
        address _governanceAddress,
        address _verifierAddress,
        address _additionalVengine,
        bytes32 _genesisStateHash
        ) = abi.decode(initializationParameters, (address, address, address, bytes32));

        verifier = Verifier(_verifierAddress);
        governance = Governance(_governanceAddress);
        additionalVengine = AdditionalVengine(_additionalVengine);

        StoredBlockInfo memory storedBlockZero = StoredBlockInfo(
            0,
            0,
            EMPTY_STRING_KECCAK,
            0,
            _genesisStateHash,
            bytes32(0)
        );
        storedBlockHashes[0] = hashStoredBlockInfo(storedBlockZero);
        approvedUpgradeNoticePeriod = UPGRADE_NOTICE_PERIOD;
        emit NoticePeriodChange(approvedUpgradeNoticePeriod);
    }

    function cutUpgradeNoticePeriod() external {
        /// All functions delegated to additional contract should NOT be nonReentrant
        delegateAdditional();
    }

    /// @notice Checks if SafeExit mode must be entered. If true - enters SafeExit mode and emits SafeExitMode event.
    /// @dev SafeExit mode must be entered in case of current ethereum block number is higher than the oldest
    /// @dev of existed priority requests expiration block number.
    /// @return bool flag that is true if the SafeExit mode must be entered.
    function activateSafeExitMode() public returns (bool) {
        // #if EASY_SAFEEXIT
        bool trigger = true;
        // #else
        bool trigger = block.number >= priorityRequests[firstPriorityRequestId].expirationBlock &&
        priorityRequests[firstPriorityRequestId].expirationBlock != 0;
        // #endif
        if (trigger) {
            if (!safeExitMode) {
                safeExitMode = true;
                emit SafeExitMode();
            }
            return true;
        } else {
            return false;
        }
    }

    /// @notice Withdraws token from Vengine to root chain in case of SafeExit mode. User must provide proof that he owns funds
    /// @param _storedBlockInfo Last verified block
    /// @param _owner Owner of the account
    /// @param _accountId Id of the account in the tree
    /// @param _proof Proof
    /// @param _tokenId Verified token id
    /// @param _amount Amount for owner (must be total amount, not part of it)
    function performSafeExit(
        StoredBlockInfo memory _storedBlockInfo,
        address _owner,
        uint32 _accountId,
        uint32 _tokenId,
        uint128 _amount,
        uint32 _nftCreatorAccountId,
        address _nftCreatorAddress,
        uint32 _nftSerialId,
        bytes32 _nftContentHash,
        uint256[] memory _proof
    ) external {
        /// All functions delegated to additional should NOT be nonReentrant
        delegateAdditional();
    }
    /// @notice Accrues users balances from deposit priority requests in SafeExit mode
    /// @dev WARNING: Only for SafeExit mode
    /// @dev Canceling may take several separate transactions to be completed
    /// @param _n number of requests to process
    function cancelOutstandingDepositsForSafeExitMode(uint64 _n, bytes[] memory _depositsPubdata) external {
        /// All functions delegated to additional contract should NOT be nonReentrant
        delegateAdditional();
    }
    /// @notice Reverts unverified blocks
    function revertBlocks(StoredBlockInfo[] memory _blocksToRevert) external {
        /// All functions delegated to additional contract should NOT be nonReentrant
        delegateAdditional();
    }


    /// @notice Set data for changing pubkey hash using onchain authorization.
    ///         Transaction author (msg.sender) should be L2 account address
    /// @notice New pubkey hash can be reset, to do that user should send two transactions:
    ///         1) First `setAuthPubkeyHash` transaction for already used `_nonce` will set timer.
    ///         2) After `AUTH_FACT_RESET_TIMELOCK` time is passed second `setAuthPubkeyHash` transaction will reset pubkey hash for `_nonce`.
    /// @param _pubkeyHash New pubkey hash
    /// @param _nonce Nonce of the update public key L2 transaction
    function setAuthPubkeyHash(bytes calldata _pubkeyHash, uint32 _nonce) external {
        /// All functions delegated to additional contract should NOT be nonReentrant
        delegateAdditional();
    }
    /// @notice Delegates the call to the additional part of the main contract.
    /// @notice Should be only use to delegate the external calls as it passes the calldata
    /// @notice All functions delegated to additional contract should NOT be nonReentrant
    function delegateAdditional() internal {
        address _target = address(additionalVengine);
        assembly {
        // The pointer to the free memory slot
            let ptr := mload(0x40)
        // Copy function signature and arguments from calldata at zero position into memory at pointer position
            calldatacopy(ptr, 0x0, calldatasize())
        // Delegatecall method of the implementation contract, returns 0 on error
            let result := delegatecall(gas(), _target, ptr, calldatasize(), 0x0, 0)
        // Get the size of the last return data
            let size := returndatasize()
        // Copy the size length of bytes from return data at zero position to pointer position
            returndatacopy(ptr, 0x0, size)

        // Depending on result value
            switch result
            case 0 {
            // End execution and revert state changes
                revert(ptr, size)
            }
            default {
            // Return data with length of size at pointers position
                return(ptr, size)
            }
        }
    }
}
