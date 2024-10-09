// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {
    IAccount,
    ACCOUNT_VALIDATION_SUCCESS_MAGIC
} from "lib/foundry-era-contracts/src/system-contracts/contracts/interfaces/IAccount.sol";
import {
    Transaction,
    MemoryTransactionHelper
} from "lib/foundry-era-contracts/src/system-contracts/contracts/libraries/MemoryTransactionHelper.sol";

import {SystemContractsCaller} from
    "lib/foundry-era-contracts/src/system-contracts/contracts/libraries/SystemContractsCaller.sol";
import {
    NONCE_HOLDER_SYSTEM_CONTRACT,
    BOOTLOADER_FORMAL_ADDRESS,
    DEPLOYER_SYSTEM_CONTRACT
} from "lib/foundry-era-contracts/src/system-contracts/contracts/Constants.sol";
import {INonceHolder} from "lib/foundry-era-contracts/src/system-contracts/contracts/interfaces/INonceHolder.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Utils} from "lib/foundry-era-contracts/src/system-contracts/contracts/libraries/Utils.sol";

contract ZkMinimalAccount is IAccount, Ownable {
    using MemoryTransactionHelper for Transaction;

    error ZkMinimalAccount__NotEnoughBalance();
    error ZkMinimalAccount__NotFromBootloader();
    error ZkMinimalAccount__NotFromBootloaderOrOwner();
    error ZkMinimalAccount__ExecutionFailed();
    error ZkMinimalAccount__FailedToPay();

    constructor() Ownable(msg.sender) {}

    receive() external payable {}
    /*//////////////////////////////////////////////////////////////
                               MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier requireFromBootloader() {
        if (msg.sender != BOOTLOADER_FORMAL_ADDRESS) {
            revert ZkMinimalAccount__NotFromBootloader();
        }
        _;
    }

    modifier requireFromBootloaderOrOwner() {
        if (msg.sender != BOOTLOADER_FORMAL_ADDRESS && msg.sender != owner()) {
            revert ZkMinimalAccount__NotFromBootloaderOrOwner();
        }
        _;
    }
    /*//////////////////////////////////////////////////////////////
                          EXTEXRNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice  Must increase the nonce
     * @notice  Must validate transaction (check the owner signed the transaction)
     * @notice  Check if we have enough money for transaction in account
     */
    function validateTransaction(bytes32, /*txHash*/ bytes32, /*suggestedSignedHash*/ Transaction calldata _transaction)
        external
        payable
        requireFromBootloader
        returns (bytes4 magic)
    {
        return _validateTransaction(_transaction);
    }

    function executeTransaction(bytes32, /*txHash*/ bytes32, /*suggestedSignedHash*/ Transaction calldata _transaction)
        external
        payable
        requireFromBootloaderOrOwner
    {
        _executeTransaction(_transaction);
    }

    function executeTransactionFromOutside(Transaction calldata _transaction) external payable {
        _validateTransaction(_transaction);
        _executeTransaction(_transaction);
    }

    function payForTransaction(
        bytes32, /* txHash */
        bytes32, /* suggestedSignedHash*/
        Transaction calldata _transaction
    ) external payable {
        bool success = _transaction.payToTheBootloader();
        if (!success) {
            revert ZkMinimalAccount__FailedToPay();
        }
    }

    function prepareForPaymaster(bytes32 txHash, bytes32 possibleSignedHash, Transaction calldata _transaction)
        external
        payable
    {
        // We don't work with paymaster
    }

    /*//////////////////////////////////////////////////////////////
                           INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _validateTransaction(Transaction calldata _transaction) internal returns (bytes4 magic) {
        // Increment nonce
        SystemContractsCaller.systemCallWithPropagatedRevert(
            uint32(gasleft()),
            address(NONCE_HOLDER_SYSTEM_CONTRACT),
            0,
            abi.encodeCall(INonceHolder.incrementMinNonceIfEquals, (_transaction.nonce))
        );

        // Check fee to pay
        uint256 totalRequiredBalance = _transaction.totalRequiredBalance();

        if (totalRequiredBalance > address(this).balance) {
            revert ZkMinimalAccount__NotEnoughBalance();
        }

        // Check the signature
        bytes32 txHash = _transaction.encodeHash();
        address signer = ECDSA.recover(txHash, _transaction.signature);

        bool isValidSigner = signer == owner();

        if (isValidSigner) {
            magic = ACCOUNT_VALIDATION_SUCCESS_MAGIC;
        } else {
            magic = bytes4(0);
        }

        return magic;
    }

    function _executeTransaction(Transaction calldata _transaction) internal {
        address to = address(uint160(_transaction.to));
        uint128 value = Utils.safeCastToU128(_transaction.value);
        bytes memory data = _transaction.data;

        // If transaction creates new contract we must call system contract
        if (to == address(DEPLOYER_SYSTEM_CONTRACT)) {
            uint32 gasLimit = Utils.safeCastToU32(gasleft());
            SystemContractsCaller.systemCallWithPropagatedRevert(gasLimit, to, value, data);
        } else {
            bool success;
            assembly {
                success := call(gas(), to, value, add(data, 0x20), mload(data), 0, 0)
            }

            if (!success) {
                revert ZkMinimalAccount__ExecutionFailed();
            }
        }
    }
}
