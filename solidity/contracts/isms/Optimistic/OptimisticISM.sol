// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.0;

import {IOptimisticIsm} from "../../interfaces/isms/IOptimisticIsm.sol";
import {IInterchainSecurityModule} from "../../interfaces/IInterchainSecurityModule.sol";
import {StaticMOfNAddressSetFactory} from "../../libs/StaticMOfNAddressSetFactory.sol";


abstract contract OptimisticISM is IOptimisticIsm {

    struct FraudWindow {
        uint256 endTimestamp;
        bool preVerified;
        mapping(address => bool) compromisedSubmodules;
    }
    
    mapping(bytes32 => FraudWindow) public fraudWindows;
    IInterchainSecurityModule private _submodule;
    address private owner;
    address[] public watchers;
    mapping(address => bool) public isWatcher;
    StaticMOfNAddressSetFactory private addressSetFactory;

    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only contract owner can perform this operation");
        _;
    }

    constructor(StaticMOfNAddressSetFactory _addressSetFactory) {
        addressSetFactory = _addressSetFactory;
        owner = msg.sender;
    }

    function configureWatchers(address[] calldata _watchers, uint8 _threshold) external onlyOwner {
        // Deploy a StaticMOfNAddressSet instance using the factory
        address addressSet = addressSetFactory.deploy(_watchers, _threshold);

        // Set the deployed addressSet as the new set of watchers
        watchers = _watchers;

        // Update the isWatcher mapping accordingly
        for (uint256 i = 0; i < _watchers.length; i++) {
            isWatcher[_watchers[i]] = true;
        }

        // Perform any other necessary configurations or actions
        // ...

        emit WatchersConfigured(addressSet, _watchers, _threshold);
    }

    event WatchersConfigured(address indexed addressSet, address[] watchers, uint8 threshold);

    function deliverMessage(bytes calldata _metadata, bytes calldata _message) external override returns (bool)  {

        bytes32 messageHash = calculateMessageHash(abi.encodePacked(_metadata, _message));
    
        // Create a new FraudWindow object
        FraudWindow storage fraudWindow = fraudWindows[messageHash];
    
        // Check if the FraudWindow already exists
        if (fraudWindow.endTimestamp != 0) {
            revert("FraudWindow already exists for this message");

        }
    
        // Set the endTimestamp of the FraudWindow
        fraudWindow.endTimestamp = block.timestamp + fraudWindowDuration();
        
        //Rest of delivery related implementation if required...
        // ...
        return true;
    }

    function preVerify(bytes calldata _metadata, bytes calldata _message) external override returns (bool) {
        bytes32 messageHash = calculateMessageHash(abi.encodePacked(_metadata, _message));

        FraudWindow storage relatedWindow = fraudWindows[messageHash];

        // Check if the fraud window has not elapsed
        require(block.timestamp >= relatedWindow.endTimestamp, "Fraud window not yet elapsed");

        // Perform pre-verification using the configured submodule
        bool isVerified = _submodule.verify(_metadata, _message);

        if (!isVerified) {
            //Depens on an another use-case mark the submodule as compromised if pre-verification fails
            //markFraudulent(address(_submodule));
        }

        return isVerified;
    }

    function verify(bytes calldata _metadata, bytes calldata _message) external view virtual override returns (bool) {
        bytes32 messageHash = calculateMessageHash(abi.encodePacked(_metadata, _message));
        FraudWindow storage fraudWindow = fraudWindows[messageHash];

        // Check if the message has been pre-verified
        if (!isPreVerified(messageHash)) {
            return false;
        }

        // Check if the submodule has been compromised
        if (fraudWindow.compromisedSubmodules[address(_submodule)]) {
            return false;
        }

        // Check if the fraud window has elapsed
        if (block.timestamp < fraudWindow.endTimestamp) {
            return false;
        }

        return true;
    }

    function isPreVerified(bytes32 messageHash) internal view returns (bool) {
        return (fraudWindows[messageHash].preVerified);
    }

    function markFraudulent(address submodule) public {
        fraudWindows[calculateMessageHash(msg.data)].compromisedSubmodules[submodule] = true;
    }

    function configureSubmodule(IInterchainSecurityModule submodule) external onlyOwner {
        _submodule = submodule;
    }

    function calculateMessageHash(bytes memory _message) internal pure returns (bytes32) {
        return keccak256(_message);
    }

    function fraudWindowDuration() internal pure returns (uint256) {
        // Implement your logic to determine the fraud window duration
        // For example, you can return a constant value or use a configurable parameter
        // This is just a placeholder implementation
        return 1 days;
    }
}
