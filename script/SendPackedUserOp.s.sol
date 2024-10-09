// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script} from "forge-std/Script.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {HelperConfig} from "script/HelperConfig.s.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract SendPackedUserOp is Script {
    using MessageHashUtils for bytes32;

    function run() public {}

    function generateSignedUserOperation(
        bytes memory _callData,
        HelperConfig.NetworkConfig memory _config,
        address minimalAccount
    ) public view returns (PackedUserOperation memory) {
        // Generate the unsigned data
        uint256 nonce = vm.getNonce(minimalAccount) - 1;
        PackedUserOperation memory userOp = _generatedUnsignedUserOperation(_callData, minimalAccount, nonce);

        // Get the user opHash
        bytes32 userOpHash = IEntryPoint(_config.entryPoint).getUserOpHash(userOp);
        bytes32 digest = userOpHash.toEthSignedMessageHash();

        // Sign it
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 ANVIL_DEFAULT_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        if (block.chainid == 31337) {
            (v, r, s) = vm.sign(ANVIL_DEFAULT_KEY, digest);
        } else {
            (v, r, s) = vm.sign(_config.account, digest);
        }
        userOp.signature = abi.encodePacked(r, s, v); // Pay atternion to the order of r, s, v
        return userOp;
    }

    function _generatedUnsignedUserOperation(bytes memory _callData, address _sender, uint256 _nonce)
        public
        pure
        returns (PackedUserOperation memory)
    {
        uint128 verificationGasLimit = 16777216;
        uint128 callGasLimit = verificationGasLimit;
        uint128 maxPriorityFeePerGas = 256;
        uint128 maxFeePerGas = maxPriorityFeePerGas;

        return PackedUserOperation({
            sender: _sender,
            nonce: _nonce,
            initCode: hex"",
            callData: _callData,
            // Just concatenates the two gas limits into a single bytes32 (256bit value)
            accountGasLimits: bytes32(uint256(verificationGasLimit) << 128 | callGasLimit),
            preVerificationGas: verificationGasLimit,
            gasFees: bytes32(uint256(maxPriorityFeePerGas) << 128 | maxFeePerGas),
            paymasterAndData: hex"",
            signature: hex""
        });
    }
}
