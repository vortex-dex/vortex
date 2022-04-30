// SPDX-License-Identifier: MIT OR Apache-2.0

pragma solidity ^0.7.0;

pragma experimental ABIEncoderV2;


import ".././security/ReentrancyGuard.sol";
import ".././utils/SafeMath.sol";
import ".././utils/SafeMathUInt128.sol";
import ".././utils/SafeCast.sol";
import ".././utils/Utils.sol";

import ".././library/Storage.sol";
import "./OperationConstants.sol";
import ".././library/Events.sol";

import ".././utils/Bytes.sol";
import ".././library/Operations.sol";

import ".././upgrade/UpgradeableMaster.sol";
import ".././library/RegenesisMultisig.sol";
import ".././AdditionalVengine.sol";

/// @title vengine block operator constants
contract BlockOperator  is Storage, OperationConstants, Events, ReentrancyGuard{


    using SafeMath for uint256;
    using SafeMathUInt128 for uint128;
    bytes32 internal constant EMPTY_STRING_KECCAK = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;

    /// @notice Data needed to process onchain operation from block public data.
    /// @notice Onchain operations is operations that need some processing on L1: Deposits, Withdrawals, UpdatePublicKey.
    /// @param ethWitness Some external data that can be needed for operation processing
    /// @param publicDataOffset Byte offset in public data for onchain operation
    struct OnchainOperationData {
        bytes ethWitness;
        uint32 publicDataOffset;
    }

    /// @notice Data needed to commit new block
    struct CommitBlockInfo {
        bytes32 newStateHash;
        bytes publicData;
        uint256 timestamp;
        OnchainOperationData[] onchainOperations;
        uint32 blockNumber;
        uint32 feeAccount;
    }

    /// @notice Data needed to execute committed and verified block
    /// @param commitmentsInSlot verified commitments in one slot
    /// @param commitmentIdx index such that commitmentsInSlot[commitmentIdx] is current block commitment
    struct ExecuteBlockInfo {
        StoredBlockInfo storedBlock;
        bytes[] pendingOnchainOpsPubdata;
    }

    /// @notice Recursive proof input data (individual commitments are constructed onchain)
    struct ProofInput {
        uint256[] recursiveInput;
        uint256[] proof;
        uint256[] commitments;
        uint8[] vkIndexes;
        uint256[16] subproofsLimbs;
    }

    /// @dev Process one block commit using previous block StoredBlockInfo,
    /// @dev returns new block StoredBlockInfo
    /// @dev NOTE: Does not change storage (except events, so we can't mark it view)
    function commitOneBlock(StoredBlockInfo memory _previousBlock, CommitBlockInfo memory _newBlock)
    internal
    view
    returns (StoredBlockInfo memory storedNewBlock)
    {
        require(_newBlock.blockNumber == _previousBlock.blockNumber + 1, "3o"); // only commit next block

        // Check timestamp of the new block
        {
            require(_newBlock.timestamp >= _previousBlock.timestamp, "3p"); // Block should be after previous block
            bool timestampNotTooSmall = block.timestamp.sub(COMMIT_TIMESTAMP_NOT_OLDER) <= _newBlock.timestamp;
            bool timestampNotTooBig = _newBlock.timestamp <= block.timestamp.add(COMMIT_TIMESTAMP_APPROXIMATION_DELTA);
            require(timestampNotTooSmall && timestampNotTooBig, "3q"); // New block timestamp is not valid
        }

        // Check onchain operations
        (
        bytes32 pendingOnchainOpsHash,
        uint64 priorityReqCommitted,
        bytes memory onchainOpsOffsetCommitment
        ) = collectOnchainOps(_newBlock);

        // Create block commitment for verification proof
        bytes32 commitment = createBlockCommitment(_previousBlock, _newBlock, onchainOpsOffsetCommitment);

        return
        StoredBlockInfo(
            _newBlock.blockNumber,
            priorityReqCommitted,
            pendingOnchainOpsHash,
            _newBlock.timestamp,
            _newBlock.newStateHash,
            commitment
        );
    }

    /// @notice Commit block
    /// @notice 1. Checks onchain operations, timestamp.
    /// @notice 2. Store block commitments
    function commitBlocks(StoredBlockInfo memory _lastCommittedBlockData, CommitBlockInfo[] memory _newBlocksData)
    external
    nonReentrant
    {
        requireActive();
        governance.requireActiveValidator(msg.sender);
        // Check that we commit blocks after last committed block
        require(storedBlockHashes[totalBlocksCommitted] == hashStoredBlockInfo(_lastCommittedBlockData), "3r"); // incorrect previous block data

        for (uint32 i = 0; i < _newBlocksData.length; ++i) {
            _lastCommittedBlockData = commitOneBlock(_lastCommittedBlockData, _newBlocksData[i]);

            totalCommittedPriorityRequests += _lastCommittedBlockData.priorityOperations;
            storedBlockHashes[_lastCommittedBlockData.blockNumber] = hashStoredBlockInfo(_lastCommittedBlockData);

            emit BlockCommit(_lastCommittedBlockData.blockNumber);
        }

        totalBlocksCommitted += uint32(_newBlocksData.length);

        require(totalCommittedPriorityRequests <= totalOpenPriorityRequests, "3s");
    }
    /// @dev Executes one block
    /// @dev 1. Processes all pending operations (Send Exits, Complete priority requests)
    /// @dev 2. Finalizes block on Ethereum
    /// @dev _executedBlockIdx is index in the array of the blocks that we want to execute together
    function executeOneBlock(ExecuteBlockInfo memory _blockExecuteData, uint32 _executedBlockIdx) internal {
        // Ensure block was committed
        require(
            hashStoredBlockInfo(_blockExecuteData.storedBlock) ==
            storedBlockHashes[_blockExecuteData.storedBlock.blockNumber],
            "3t" // executing block should be committed
        );
        require(_blockExecuteData.storedBlock.blockNumber == totalBlocksExecuted + _executedBlockIdx + 1, "3u"); // Execute blocks in order

        bytes32 pendingOnchainOpsHash = EMPTY_STRING_KECCAK;
        for (uint32 i = 0; i < _blockExecuteData.pendingOnchainOpsPubdata.length; ++i) {
            bytes memory pubData = _blockExecuteData.pendingOnchainOpsPubdata[i];

            Operations.OpType opType = Operations.OpType(uint8(pubData[0]));

            if (opType == Operations.OpType.PartialExit) {
                Operations.PartialExit memory op = Operations.readPartialExitPubdata(pubData);
                // Circuit guarantees that partial exits are available only for fungible tokens
                require(op.tokenId <= MAX_FUNGIBLE_TOKEN_ID, "3v");
                withdrawOrStore(uint16(op.tokenId), op.owner, op.amount);
            } else if (opType == Operations.OpType.ForcedWithdraw) {
                Operations.ForcedWithdraw memory op = Operations.readForcedWithdrawPubdata(pubData);
                // Circuit guarantees that forced withdraws are available only for fungible tokens
                require(op.tokenId <= MAX_FUNGIBLE_TOKEN_ID, "3w");
                withdrawOrStore(uint16(op.tokenId), op.target, op.amount);
            } else if (opType == Operations.OpType.FullWithdraw) {
                Operations.FullWithdraw memory op = Operations.readFullWithdrawPubdata(pubData);
                if (op.tokenId <= MAX_FUNGIBLE_TOKEN_ID) {
                    withdrawOrStore(uint16(op.tokenId), op.owner, op.amount);
                } else {
                    if (op.amount == 1) {
                        Operations.WithdrawNFT memory withdrawNftOp = Operations.WithdrawNFT(
                            op.nftCreatorAccountId,
                            op.nftCreatorAddress,
                            op.nftSerialId,
                            op.nftContentHash,
                            op.owner,
                            op.tokenId
                        );
                        withdrawOrStoreNFT(withdrawNftOp);
                    }
                }
            } else if (opType == Operations.OpType.WithdrawNFT) {
                Operations.WithdrawNFT memory op = Operations.readWithdrawNFTPubdata(pubData);
                withdrawOrStoreNFT(op);
            } else {
                revert("3x"); // unsupported op in block execution
            }

            pendingOnchainOpsHash = Utils.concatHash(pendingOnchainOpsHash, pubData);
        }
        require(pendingOnchainOpsHash == _blockExecuteData.storedBlock.pendingOnchainOperationsHash, "3y"); // incorrect onchain ops executed
    }

    /// @notice Execute blocks, completing priority operations and processing withdrawals.
    /// @notice 1. Processes all pending operations (Send Exits, Complete priority requests)
    /// @notice 2. Finalizes block on Ethereum
    function executeBlocks(ExecuteBlockInfo[] memory _blocksData) external nonReentrant {
        requireActive();
        governance.requireActiveValidator(msg.sender);

        uint64 priorityRequestsExecuted = 0;
        uint32 nBlocks = uint32(_blocksData.length);
        for (uint32 i = 0; i < nBlocks; ++i) {
            executeOneBlock(_blocksData[i], i);
            priorityRequestsExecuted += _blocksData[i].storedBlock.priorityOperations;
            emit BlockVerification(_blocksData[i].storedBlock.blockNumber);
        }

        firstPriorityRequestId += priorityRequestsExecuted;
        totalCommittedPriorityRequests -= priorityRequestsExecuted;
        totalOpenPriorityRequests -= priorityRequestsExecuted;

        totalBlocksExecuted += nBlocks;
        require(totalBlocksExecuted <= totalBlocksProven, "3z"); // Can't execute blocks more then committed and proven currently.
    }

    /// @notice Blocks commitment verification.
    /// @notice Only verifies block commitments without any other processing
    function proveBlocks(StoredBlockInfo[] memory _committedBlocks, ProofInput memory _proof) external nonReentrant {
        requireActive();

        uint32 currentTotalBlocksProven = totalBlocksProven;
        for (uint256 i = 0; i < _committedBlocks.length; ++i) {
            require(hashStoredBlockInfo(_committedBlocks[i]) == storedBlockHashes[currentTotalBlocksProven + 1], "3aa");
            ++currentTotalBlocksProven;

            require(_proof.commitments[i] & INPUT_MASK == uint256(_committedBlocks[i].commitment) & INPUT_MASK, "3ab"); // incorrect block commitment in proof
        }

        bool success = verifier.verifyAggregatedBlockProof(
            _proof.recursiveInput,
            _proof.proof,
            _proof.vkIndexes,
            _proof.commitments,
            _proof.subproofsLimbs
        );
        require(success, "3ac"); // Aggregated proof verification fail

        require(currentTotalBlocksProven <= totalBlocksCommitted, "3ad");
        totalBlocksProven = currentTotalBlocksProven;
    }

    /// @dev Gets operations packed in bytes array. Unpacks it and stores onchain operations.
    /// @dev Priority operations must be committed in the same order as they are in the priority queue.
    /// @dev NOTE: does not change storage! (only emits events)
    /// @dev processableOperationsHash - hash of the all operations that needs to be executed  (Deposit, Exits, ChangPubKey)
    /// @dev priorityOperationsProcessed - number of priority operations processed in this block (Deposits, FullWithdraws)
    /// @dev offsetsCommitment - array where 1 is stored in chunk where onchainOperation begins and other are 0 (used in commitments)
    function collectOnchainOps(CommitBlockInfo memory _newBlockData)
    internal
    view
    returns (
        bytes32 processableOperationsHash,
        uint64 priorityOperationsProcessed,
        bytes memory offsetsCommitment
    )
    {
        bytes memory pubData = _newBlockData.publicData;

        uint64 uncommittedPriorityRequestsOffset = firstPriorityRequestId + totalCommittedPriorityRequests;
        priorityOperationsProcessed = 0;
        processableOperationsHash = EMPTY_STRING_KECCAK;

        require(pubData.length % CHUNK_BYTES == 0, "3ae"); // pubdata length must be a multiple of CHUNK_BYTES
        offsetsCommitment = new bytes(pubData.length / CHUNK_BYTES);
        for (uint256 i = 0; i < _newBlockData.onchainOperations.length; ++i) {
            OnchainOperationData memory onchainOpData = _newBlockData.onchainOperations[i];

            uint256 pubdataOffset = onchainOpData.publicDataOffset;
            require(pubdataOffset < pubData.length, "3af");
            require(pubdataOffset % CHUNK_BYTES == 0, "3ag"); // offsets should be on chunks boundaries
            uint256 chunkId = pubdataOffset / CHUNK_BYTES;
            require(offsetsCommitment[chunkId] == 0x00, "3ah"); // offset commitment should be empty
            offsetsCommitment[chunkId] = bytes1(0x01);

            Operations.OpType opType = Operations.OpType(uint8(pubData[pubdataOffset]));

            if (opType == Operations.OpType.Deposit) {
                bytes memory opPubData = Bytes.slice(pubData, pubdataOffset, DEPOSIT_BYTES);

                Operations.Deposit memory depositData = Operations.readDepositPubdata(opPubData);

                checkPriorityOperation(depositData, uncommittedPriorityRequestsOffset + priorityOperationsProcessed);
                priorityOperationsProcessed++;
            } else if (opType == Operations.OpType.UpdatePublicKey) {
                bytes memory opPubData = Bytes.slice(pubData, pubdataOffset, UPDATE_PUBLIC_KEY_BYTES);

                Operations.UpdatePublicKey memory op = Operations.readUpdatePublicKeyPubdata(opPubData);

                if (onchainOpData.ethWitness.length != 0) {
                    bool valid = verifyUpdatePublicKey(onchainOpData.ethWitness, op);
                    require(valid, "3ai"); // failed to verify update public key hash signature
                } else {
                    bool valid = authFacts[op.owner][op.nonce] == keccak256(abi.encodePacked(op.pubKeyHash));
                    require(valid, "3aj"); // new pub key hash is not authenticated properly
                }
            } else {
                bytes memory opPubData;

                if (opType == Operations.OpType.PartialExit) {
                    opPubData = Bytes.slice(pubData, pubdataOffset, PARTIAL_EXIT_BYTES);
                } else if (opType == Operations.OpType.ForcedWithdraw) {
                    opPubData = Bytes.slice(pubData, pubdataOffset, FORCED_WITHDRAW_BYTES);
                } else if (opType == Operations.OpType.WithdrawNFT) {
                    opPubData = Bytes.slice(pubData, pubdataOffset, WITHDRAW_NFT_BYTES);
                } else if (opType == Operations.OpType.FullWithdraw) {
                    opPubData = Bytes.slice(pubData, pubdataOffset, FULL_WITHDRAW_BYTES);

                    Operations.FullWithdraw memory fullWithdrawData = Operations.readFullWithdrawPubdata(opPubData);

                    checkPriorityOperation(
                        fullWithdrawData,
                        uncommittedPriorityRequestsOffset + priorityOperationsProcessed
                    );
                    priorityOperationsProcessed++;
                } else {
                    revert("3ak"); // unsupported op
                }

                processableOperationsHash = Utils.concatHash(processableOperationsHash, opPubData);
            }
        }
    }
    /// @dev Creates block commitment from its data
    /// @dev _offsetCommitment - hash of the array where 1 is stored in chunk where onchainOperation begins and 0 for other chunks
    function createBlockCommitment(
        StoredBlockInfo memory _previousBlock,
        CommitBlockInfo memory _newBlockData,
        bytes memory _offsetCommitment
    ) internal view returns (bytes32 commitment) {
        bytes32 hash = sha256(abi.encodePacked(uint256(_newBlockData.blockNumber), uint256(_newBlockData.feeAccount)));
        hash = sha256(abi.encodePacked(hash, _previousBlock.stateHash));
        hash = sha256(abi.encodePacked(hash, _newBlockData.newStateHash));
        hash = sha256(abi.encodePacked(hash, uint256(_newBlockData.timestamp)));

        bytes memory pubdata = abi.encodePacked(_newBlockData.publicData, _offsetCommitment);

        /// The code below is equivalent to `commitment = sha256(abi.encodePacked(hash, _publicData))`

        /// We use inline assembly instead of this concise and readable code in order to avoid copying of `_publicData` (which saves ~90 gas per transfer operation).

        /// Specifically, we perform the following trick:
        /// First, replace the first 32 bytes of `_publicData` (where normally its length is stored) with the value of `hash`.
        /// Then, we call `sha256` precompile passing the `_publicData` pointer and the length of the concatenated byte buffer.
        /// Finally, we put the `_publicData.length` back to its original location (to the first word of `_publicData`).
        assembly {
            let hashResult := mload(0x40)
            let pubDataLen := mload(pubdata)
            mstore(pubdata, hash)
        // staticcall to the sha256 precompile at address 0x2
            let success := staticcall(gas(), 0x2, pubdata, add(pubDataLen, 0x20), hashResult, 0x20)
            mstore(pubdata, pubDataLen)

        // Use "invalid" to make gas estimation work
            switch success
            case 0 {
                invalid()
            }

            commitment := mload(hashResult)
        }
    }


    /// @dev 1. Try to send token to _recipients
    /// @dev 2. On failure: Increment _recipients balance to withdraw.
    function withdrawOrStoreNFT(Operations.WithdrawNFT memory op) internal {
        NFTFactory _factory = governance.getNFTFactory(op.creatorAccountId, op.creatorAddress);
        try
        _factory.mintNFTFromVengine{gas: WITHDRAWAL_NFT_GAS_LIMIT}(
            op.creatorAddress,
            op.receiver,
            op.creatorAccountId,
            op.serialId,
            op.contentHash,
            op.tokenId
        )
        {
            // Save withdrawn nfts for future deposits
            withdrawnNFTs[op.tokenId] = address(_factory);
            emit WithdrawalNFT(op.tokenId);
        } catch {
            pendingWithdrawnNFTs[op.tokenId] = op;
            emit WithdrawalNFTPending(op.tokenId);
        }
    }

    /// @dev 1. Try to send token to _recipients
    /// @dev 2. On failure: Increment _recipients balance to withdraw.
    function withdrawOrStore(
        uint16 _tokenId,
        address _recipient,
        uint128 _amount
    ) internal {
        bytes22 packedBalanceKey = packAddressAndTokenId(_recipient, _tokenId);

        bool sent = false;
        if (_tokenId == 0) {
            address payable toPayable = address(uint160(_recipient));
            sent = sendETHNoRevert(toPayable, _amount);
        } else {
            address tokenAddr = governance.tokenAddresses(_tokenId);
            // We use `_transferERC20` here to check that `ERC20` token indeed transferred `_amount`
            // and fail if token subtracted from vengine balance more then `_amount` that was requested.
            // This can happen if token subtracts fee from sender while transferring `_amount` that was requested to transfer.
            try this._transferERC20{gas: WITHDRAWAL_GAS_LIMIT}(IERC20(tokenAddr), _recipient, _amount, _amount) {
                sent = true;
            } catch {
                sent = false;
            }
        }
        if (sent) {
            emit Withdrawal(_tokenId, _amount);
        } else {
            increaseBalanceToWithdraw(packedBalanceKey, _amount);
            emit WithdrawalPending(_tokenId, _amount);
        }
    }

    /// @notice Sends tokens
    /// @dev NOTE: will revert if transfer call fails or rollup balance difference (before and after transfer) is bigger than _maxAmount
    /// @dev This function is used to allow tokens to spend vengine contract balance up to amount that is requested
    /// @param _token Token address
    /// @param _to Address of recipient
    /// @param _amount Amount of tokens to transfer
    /// @param _maxAmount Maximum possible amount of tokens to transfer to this account
    function _transferERC20(
        IERC20 _token,
        address _to,
        uint128 _amount,
        uint128 _maxAmount
    ) external returns (uint128 withdrawnAmount) {
        require(msg.sender == address(this), "3a"); // wtg10 - can be called only from this contract as one "external" call (to revert all this function state changes if it is needed)

        uint256 balanceBefore = _token.balanceOf(address(this));
        require(Utils.sendERC20(_token, _to, _amount), "3b"); // wtg11 - ERC20 transfer fails
        uint256 balanceAfter = _token.balanceOf(address(this));
        uint256 balanceDiff = balanceBefore.sub(balanceAfter);
        require(balanceDiff <= _maxAmount, "3c"); // wtg12 - rollup balance difference (before and after transfer) is bigger than _maxAmount

        return SafeCast.toUint128(balanceDiff);
    }

    /// @notice Checks that change operation is correct
    function verifyUpdatePublicKey(bytes memory _ethWitness, Operations.UpdatePublicKey memory _changePk)
    internal
    pure
    returns (bool)
    {
        Operations.UpdatePublicKeyType changePkType = Operations.UpdatePublicKeyType(uint8(_ethWitness[0]));
        if (changePkType == Operations.UpdatePublicKeyType.ECRECOVER) {
            return verifyUpdatePublicKeyECRECOVER(_ethWitness, _changePk);
        } else if (changePkType == Operations.UpdatePublicKeyType.CREATE2) {
            return verifyUpdatePublicKeyCREATE2(_ethWitness, _changePk);
        } else if (changePkType == Operations.UpdatePublicKeyType.OldECRECOVER) {
            return verifyUpdatePublicKeyOldECRECOVER(_ethWitness, _changePk);
        } else if (changePkType == Operations.UpdatePublicKeyType.ECRECOVERV2) {
            return verifyUpdatePublicKeyECRECOVERV2(_ethWitness, _changePk);
        } else {
            revert("3al"); // Incorrect UpdatePublicKey type
        }
    }

    /// @notice Checks that signature is valid for pubkey change message
    /// @param _ethWitness Signature (65 bytes)
    /// @param _changePk Parsed update public key operation
    function verifyUpdatePublicKeyECRECOVER(bytes memory _ethWitness, Operations.UpdatePublicKey memory _changePk)
    internal
    pure
    returns (bool)
    {
        (, bytes memory signature) = Bytes.read(_ethWitness, 1, 65); // offset is 1 because we skip type of UpdatePublicKey
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n60",
                _changePk.pubKeyHash,
                _changePk.nonce,
                _changePk.accountId,
                bytes32(0)
            )
        );
        address recoveredAddress = Utils.recoverAddressFromEthSignature(signature, messageHash);
        return recoveredAddress == _changePk.owner && recoveredAddress != address(0);
    }

    /// @notice Checks that signature is valid for pubkey change message
    /// @param _ethWitness Signature (65 bytes) + 32 bytes of the arbitrary signed data
    /// @notice additional 32 bytes can be used to sign batches and UpdatePublicKey with one signature
    /// @param _changePk Parsed update public key operation
    function verifyUpdatePublicKeyECRECOVERV2(bytes memory _ethWitness, Operations.UpdatePublicKey memory _changePk)
    internal
    pure
    returns (bool)
    {
        (uint256 offset, bytes memory signature) = Bytes.read(_ethWitness, 1, 65); // offset is 1 because we skip type of UpdatePublicKey
        (, bytes32 additionalData) = Bytes.readBytes32(_ethWitness, offset);
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n60",
                _changePk.pubKeyHash,
                _changePk.nonce,
                _changePk.accountId,
                additionalData
            )
        );
        address recoveredAddress = Utils.recoverAddressFromEthSignature(signature, messageHash);
        return recoveredAddress == _changePk.owner && recoveredAddress != address(0);
    }

    /// @notice Checks that signature is valid for pubkey change message, old version differs by form of the signed message.
    /// @param _ethWitness Signature (65 bytes)
    /// @param _changePk Parsed update public key operation
    function verifyUpdatePublicKeyOldECRECOVER(bytes memory _ethWitness, Operations.UpdatePublicKey memory _changePk)
    internal
    pure
    returns (bool)
    {
        (, bytes memory signature) = Bytes.read(_ethWitness, 1, 65); // offset is 1 because we skip type of UpdatePublicKey
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19Ethereum Signed Message:\n152",
                "Register vengine pubkey:\n\n",
                Bytes.bytesToHexASCIIBytes(abi.encodePacked(_changePk.pubKeyHash)),
                "\n",
                "nonce: 0x",
                Bytes.bytesToHexASCIIBytes(Bytes.toBytesFromUInt32(_changePk.nonce)),
                "\n",
                "account id: 0x",
                Bytes.bytesToHexASCIIBytes(Bytes.toBytesFromUInt32(_changePk.accountId)),
                "\n\n",
                "Only sign this message for a trusted client!"
            )
        );
        address recoveredAddress = Utils.recoverAddressFromEthSignature(signature, messageHash);
        return recoveredAddress == _changePk.owner && recoveredAddress != address(0);
    }

    /// @notice Checks that signature is valid for pubkey change message
    /// @param _ethWitness Create2 deployer address, saltArg, codeHash
    /// @param _changePk Parsed update public key operation
    function verifyUpdatePublicKeyCREATE2(bytes memory _ethWitness, Operations.UpdatePublicKey memory _changePk)
    internal
    pure
    returns (bool)
    {
        address creatorAddress;
        bytes32 saltArg; // salt arg is additional bytes that are encoded in the CREATE2 salt
        bytes32 codeHash;
        uint256 offset = 1; // offset is 1 because we skip type of UpdatePublicKey
        (offset, creatorAddress) = Bytes.readAddress(_ethWitness, offset);
        (offset, saltArg) = Bytes.readBytes32(_ethWitness, offset);
        (offset, codeHash) = Bytes.readBytes32(_ethWitness, offset);
        // salt from CREATE2 specification
        bytes32 salt = keccak256(abi.encodePacked(saltArg, _changePk.pubKeyHash));
        // Address computation according to CREATE2 definition: https://eips.ethereum.org/EIPS/eip-1014
        address recoveredAddress = address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), creatorAddress, salt, codeHash))))
        );
        // This type of update public key can be done only once
        return recoveredAddress == _changePk.owner && _changePk.nonce == 0;
    }

    function increaseBalanceToWithdraw(bytes22 _packedBalanceKey, uint128 _amount) internal {
        uint128 balance = pendingBalances[_packedBalanceKey].balanceToWithdraw;
        pendingBalances[_packedBalanceKey] = PendingBalance(balance.add(_amount), FILLED_GAS_RESERVE_VALUE);
    }
    /// @notice Sends ETH
    /// @param _to Address of recipient
    /// @param _amount Amount of tokens to transfer
    /// @return bool flag indicating that transfer is successful
    function sendETHNoRevert(address payable _to, uint256 _amount) internal returns (bool) {
        (bool callSuccess, ) = _to.call{gas: WITHDRAWAL_GAS_LIMIT, value: _amount}("");
        return callSuccess;
    }

    /// @notice  Withdraws tokens from vengine contract to the owner
    /// @param _owner Address of the tokens owner
    /// @param _token Address of tokens, zero address is used for ETH
    /// @param _amount Amount to withdraw to request.
    ///         NOTE: We will call ERC20.transfer(.., _amount), but if according to internal logic of ERC20 token vengine contract
    ///         balance will be decreased by value more then _amount we will try to subtract this value from user pending balance
    function withdrawPendingBalance(
        address payable _owner,
        address _token,
        uint128 _amount
    ) external nonReentrant {
        if (_token == address(0)) {
            registerWithdrawal(0, _amount, _owner);
            (bool success, ) = _owner.call{value: _amount}("");
            require(success, "3h"); // ETH withdraw failed
        } else {
            uint16 tokenId = governance.validateTokenAddress(_token);
            bytes22 packedBalanceKey = packAddressAndTokenId(_owner, tokenId);
            uint128 balance = pendingBalances[packedBalanceKey].balanceToWithdraw;
            // We will allow withdrawals of `value` such that:
            // `value` <= user pending balance
            // `value` can be bigger then `_amount` requested if token takes fee from sender in addition to `_amount` requested
            uint128 withdrawnAmount = this._transferERC20(IERC20(_token), _owner, _amount, balance);
            registerWithdrawal(tokenId, withdrawnAmount, _owner);
        }
    }

    /// @notice  Withdraws NFT from vengine contract to the owner
    /// @param _tokenId Id of NFT token
    function withdrawPendingNFTBalance(uint32 _tokenId) external nonReentrant {
        Operations.WithdrawNFT memory op = pendingWithdrawnNFTs[_tokenId];
        require(op.creatorAddress != address(0), "3i"); // No NFT to withdraw
        NFTFactory _factory = governance.getNFTFactory(op.creatorAccountId, op.creatorAddress);
        _factory.mintNFTFromVengine(
            op.creatorAddress,
            op.receiver,
            op.creatorAccountId,
            op.serialId,
            op.contentHash,
            op.tokenId
        );
        // Save withdrawn nfts for future deposits
        withdrawnNFTs[op.tokenId] = address(_factory);
        emit WithdrawalNFT(op.tokenId);
        delete pendingWithdrawnNFTs[_tokenId];
    }

    /// @notice Returns amount of tokens that can be withdrawn by `address` from vengine contract
    /// @param _address Address of the tokens owner
    /// @param _token Address of token, zero address is used for ETH
    function getPendingBalance(address _address, address _token) public view returns (uint128) {
        uint16 tokenId = 0;
        if (_token != address(0)) {
            tokenId = governance.validateTokenAddress(_token);
        }
        return pendingBalances[packAddressAndTokenId(_address, tokenId)].balanceToWithdraw;
    }


    /// @notice Register withdrawal - update user balance and emit OnchainWithdrawal event
    /// @param _token - token by id
    /// @param _amount - token amount
    /// @param _to - address to withdraw to
    function registerWithdrawal(
        uint16 _token,
        uint128 _amount,
        address payable _to
    ) internal {
        bytes22 packedBalanceKey = packAddressAndTokenId(_to, _token);
        uint128 balance = pendingBalances[packedBalanceKey].balanceToWithdraw;
        pendingBalances[packedBalanceKey].balanceToWithdraw = balance.sub(_amount);
        emit Withdrawal(_token, _amount);
    }

    /// @notice Checks that deposit is same as operation in priority queue
    /// @param _deposit Deposit data
    /// @param _priorityRequestId Operation's id in priority queue
    function checkPriorityOperation(Operations.Deposit memory _deposit, uint64 _priorityRequestId) internal view {
        Operations.OpType priorReqType = priorityRequests[_priorityRequestId].opType;
        require(priorReqType == Operations.OpType.Deposit, "3am"); // incorrect priority op type

        bytes20 hashedPubdata = priorityRequests[_priorityRequestId].hashedPubData;
        require(Operations.checkDepositInPriorityQueue(_deposit, hashedPubdata), "3an");
    }

    /// @notice Checks that FullWithdraw is same as operation in priority queue
    /// @param _fullWithdraw FullWithdraw data
    /// @param _priorityRequestId Operation's id in priority queue
    function checkPriorityOperation(Operations.FullWithdraw memory _fullWithdraw, uint64 _priorityRequestId) internal view {
        Operations.OpType priorReqType = priorityRequests[_priorityRequestId].opType;
        require(priorReqType == Operations.OpType.FullWithdraw, "3ao"); // incorrect priority op type

        bytes20 hashedPubdata = priorityRequests[_priorityRequestId].hashedPubData;
        require(Operations.checkFullWithdrawInPriorityQueue(_fullWithdraw, hashedPubdata), "3ap");
    }




}
