// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "truffle/Assert.sol";
import "../isms/Optimistic/OptimisticISM.sol";

contract TestOptimisticISM {
    OptimisticISM public optimisticISM;

    function beforeEach() public {
        // Deploy a new instance of OptimisticISM
        optimisticISM = new OptimisticISM();
    }

    function testConfigureWatchers() public {
        address[] memory watchers = new address[](3);
        watchers[0] = address(0x1);
        watchers[1] = address(0x2);
        watchers[2] = address(0x3);
        uint8 threshold = 2;

        // Configure the watchers
        optimisticISM.configureWatchers(watchers, threshold);

        // Verify that the watchers and threshold are set correctly
        Assert.equal(optimisticISM.watchers(0), watchers[0], "Watcher 0 should be set");
        Assert.equal(optimisticISM.watchers(1), watchers[1], "Watcher 1 should be set");
        Assert.equal(optimisticISM.watchers(2), watchers[2], "Watcher 2 should be set");
        Assert.equal(optimisticISM.threshold(), threshold, "Threshold should be set");
    }

    function testDeliverMessage() public {
        // Configure the watchers
        address[] memory watchers = new address[](2);
        watchers[0] = address(0x1);
        watchers[1] = address(0x2);
        uint8 threshold = 1;
        optimisticISM.configureWatchers(watchers, threshold);

        // Deliver a message
        bytes memory message = abi.encode("Hello, World!");
        bool success = optimisticISM.deliverMessage(message);

        // Verify that the message was delivered successfully
        Assert.isTrue(success, "Message delivery should succeed");
    }
}