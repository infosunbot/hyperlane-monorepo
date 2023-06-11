// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

import {IInterchainSecurityModule} from "../IInterchainSecurityModule.sol";

interface IOptimisticIsm is IInterchainSecurityModule {
    function triggerMessageDelivery(bytes calldata _metadata, bytes calldata _message) external returns (bool);
	function preVerify(bytes calldata _metadata, bytes calldata _message) external returns (bool);
	function markFraudulent(address _submodule) external;
	function getSubmodule(bytes calldata _message) external view returns (IInterchainSecurityModule);
}