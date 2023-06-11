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
    address  private _addressSetFactory;

    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only contract owner can perform this operation");
        _;
    }

    constructor(address addressSetFactory) {
        _addressSetFactory = addressSetFactory;
        owner = msg.sender;
    }

            /**
            *Important Requires an additional step to deploy and obtain the StaticMOfNAddressSetFactory contract address before deploying the OptimisticISM contract.
     * @notice  allows the contract owner to configure the watchers by providing an array of watcher addresses and a threshold value. 
     It deploys a new instance of the StaticMOfNAddressSet contract using the StaticMOfNAddressSetFactory 
     and passes the provided watcher addresses and threshold to the factory's deploy function. 
     The deployed StaticMOfNAddressSet contract's address is stored, and the watchers array and isWatcher mapping are updated accordingly.
     * @param _watchers passes the provided watcher addresses.
     * @param _threshold thresholds to the factory's deploy function.
     */
    function configureWatchers(address[] calldata _watchers, uint8 _threshold) external onlyOwner {
        // Deploy a StaticMOfNAddressSet instance using the provided addressSetFactory
        StaticMOfNAddressSetFactory addressSetFactory = StaticMOfNAddressSetFactory(_addressSetFactory);
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

        /**
     * @notice Starts the fraud window. both _metadata and _message params required to be able to have a messageHash for next functions on queryiying the FraudWindow
     * @param _metadata The metadata associated with the message.
     * @param _message The message to be delivered.
     * @return True if the fraud window has started
     */
    function triggerMessageDelivery(bytes calldata _metadata, bytes calldata _message) external override returns (bool)  {

        bytes32 messageHash = calculateMessageHash(abi.encodePacked(_metadata, _message));
    
        // Create a new FraudWindow object
        FraudWindow storage fraudWindow = fraudWindows[messageHash];
    
        // Check if the FraudWindow already exists
        if (fraudWindow.endTimestamp != 0) {
            revert("FraudWindow already exists for this message");

        }
    
        // Set the endTimestamp of the FraudWindow
        fraudWindow.endTimestamp = block.timestamp + fraudWindowDuration();
        
        return true;
    }

      /**
     * @notice It will be auto-triggered once verify function works flawless and return true, Rest of delivery related implementation if there are non-implemented use-cases
     * @return True if the rest of delivery implementations work well
     */
    function completeDeliveryProcess() internal pure returns (bool) {
        
        bool isDeliveryOK;
        //Rest of delivery related implementation if required...
        // 

        return isDeliveryOK;

    }

        /**
     * @notice Verifies a message using the submodule
     * @param _metadata The metadata associated with the message.
     * @param _message The message to be verified.
     * @return True if the message is verified and the fraud window has elapsed, false otherwise.
     */
    function preVerify(bytes calldata _metadata, bytes calldata _message) external override returns (bool) {
        bytes32 messageHash = calculateMessageHash(abi.encodePacked(_metadata, _message));

        FraudWindow storage relatedWindow = fraudWindows[messageHash];

        // Check if the fraud window has not elapsed
        require(block.timestamp >= relatedWindow.endTimestamp, "Fraud window not yet elapsed");

        // Perform pre-verification using the configured submodule
        bool isVerified = _submodule.verify(_metadata, _message);

        //function may call more than 1 so relatedWindow will hold last preVerified state
        if (isVerified) { relatedWindow.preVerified = true; }
        else { relatedWindow.preVerified = false; }

        return isVerified;
    }


        /**
     * @notice Verifies a message using the submodule and checks if the submodule has been compromised and checks if the fraud window has elapsed.
     * @param _metadata The metadata associated with the message.
     * @param _message The message to be verified.
     * @return True if the message is verified and the fraud window has elapsed, false otherwise.
     */
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

        //continue the delivery process
        completeDeliveryProcess();

        return true;
    }

    /**
     * @notice An internal function; first finds relatedFraudWindows with messageHash and checks last preVerified state
     * @param messageHash first calculated on triggerMessageDelivery function. helps to find related Fraud-Window
     * @return True if the message last pre-verification ok, false otherwise.
     */
    function isPreVerified(bytes32 messageHash) internal view returns (bool) {
        return (fraudWindows[messageHash].preVerified);
    }

    function markFraudulent(address submodule) public {
        fraudWindows[calculateMessageHash(msg.data)].compromisedSubmodules[submodule] = true;
    }

        /**
     * @notice Only Contract Owner could configure submodule accordingly
     */
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
