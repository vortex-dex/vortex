// SPDX-License-Identifier: MIT OR Apache-2.0

pragma solidity ^0.7.0;

pragma experimental ABIEncoderV2;
import "./UpgradeableMaster.sol";
import ".././library/Constants.sol";
import ".././library/Storage.sol";
import ".././library/Events.sol";

import ".././utils/SafeMath.sol";
import ".././utils/SafeMathUInt128.sol";
import ".././utils/SafeCast.sol";
import ".././utils/Utils.sol";



/// @title vengine main contract
contract Upgrade is Storage, Constants, Events,UpgradeableMaster{

    using SafeMath for uint256;
    using SafeMathUInt128 for uint128;
    // Upgrade functional

    /// @notice Notice period before activation preparation status of upgrade mode
    function getNoticePeriod() virtual external pure override returns (uint256) {
        return 0;
    }

    /// @notice Notification that upgrade notice period startedwithdrawOrStore
    /// @dev Can be external because Proxy contract intercepts illegal calls of this function
    function upgradeNoticePeriodStarted() virtual external override {
        upgradeStartTimestamp = block.timestamp;
    }

    /// @notice Notification that upgrade preparation status is activated
    /// @dev Can be external because Proxy contract intercepts illegal calls of this function
    function upgradePreparationStarted() virtual external override {
        upgradePreparationActive = true;
        upgradePreparationActivationTime = block.timestamp;

        require(block.timestamp >= upgradeStartTimestamp.add(approvedUpgradeNoticePeriod));
    }

    /// @dev When upgrade is finished or canceled we must clean upgrade-related state.
    function clearUpgradeStatus() virtual internal {
        upgradePreparationActive = false;
        upgradePreparationActivationTime = 0;
        approvedUpgradeNoticePeriod = UPGRADE_NOTICE_PERIOD;
        emit NoticePeriodChange(approvedUpgradeNoticePeriod);
        upgradeStartTimestamp = 0;
        for (uint256 i = 0; i < SECURITY_COUNCIL_MEMBERS_NUMBER; ++i) {
            securityCouncilApproves[i] = false;
        }
        numberOfApprovalsFromSecurityCouncil = 0;
    }

    /// @notice Notification that upgrade canceled
    /// @dev Can be external because Proxy contract intercepts illegal calls of this function
    function upgradeCanceled() virtual external override {
        clearUpgradeStatus();
    }

    /// @notice Notification that upgrade finishes
    /// @dev Can be external because Proxy contract intercepts illegal calls of this function
    function upgradeFinishes() virtual external override {
        clearUpgradeStatus();
    }

    /// @notice Checks that contract is ready for upgrade
    /// @return bool flag indicating that contract is ready for upgrade
    function isReadyForUpgrade() virtual external view override returns (bool) {
        return !safeExitMode;
    }


}
