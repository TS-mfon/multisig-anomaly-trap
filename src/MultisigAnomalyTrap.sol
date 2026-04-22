// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;

import {Trap} from "drosera-contracts/Trap.sol";

/// @title MultisigAnomalyTrap
/// @notice Detects compromised admin key attacks (Radiant Capital style - $50M)
/// @dev Monitors ownership and admin function calls for anomalies

interface IOwnable {
    function owner() external view returns (address);
}

interface ITimelockController {
    function getMinDelay() external view returns (uint256);
}

struct CollectOutput {
    address currentOwner;
    uint256 timelockDelay;
    bytes32 codeHash;
    uint256 blockNumber;
}

contract MultisigAnomalyTrap is Trap {
    // Protocol to monitor
    address public constant MONITORED_PROTOCOL = 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2;
    address public constant TIMELOCK = 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2;

    constructor() {}

    function collect() external view override returns (bytes memory) {
        address currentOwner;
        uint256 timelockDelay;
        bytes32 codeHash;

        try IOwnable(MONITORED_PROTOCOL).owner() returns (address _owner) {
            currentOwner = _owner;
        } catch {
            currentOwner = address(0);
        }

        try ITimelockController(TIMELOCK).getMinDelay() returns (uint256 delay) {
            timelockDelay = delay;
        } catch {
            timelockDelay = 0;
        }

        // Monitor contract code hash to detect proxy upgrades
        codeHash = MONITORED_PROTOCOL.codehash;

        return abi.encode(CollectOutput({
            currentOwner: currentOwner,
            timelockDelay: timelockDelay,
            codeHash: codeHash,
            blockNumber: block.number
        }));
    }

    function shouldRespond(
        bytes[] calldata data
    ) external pure override returns (bool, bytes memory) {
        if (data.length < 2) return (false, bytes(""));

        CollectOutput memory current = abi.decode(data[0], (CollectOutput));
        CollectOutput memory previous = abi.decode(data[1], (CollectOutput));

        // Detect ownership change
        if (current.currentOwner != previous.currentOwner &&
            previous.currentOwner != address(0) &&
            current.currentOwner != address(0)) {
            return (true, bytes("Admin key compromise: ownership changed"));
        }

        // Detect timelock bypass (delay reduced to 0)
        if (previous.timelockDelay > 0 && current.timelockDelay == 0) {
            return (true, bytes("Timelock bypass: delay reduced to zero"));
        }

        // Detect timelock weakening (delay reduced by more than 50%)
        if (previous.timelockDelay > 0 && current.timelockDelay < previous.timelockDelay / 2) {
            return (true, bytes("Timelock weakened: delay reduced by >50%"));
        }

        // Detect contract code change (proxy upgrade)
        if (current.codeHash != previous.codeHash &&
            previous.codeHash != bytes32(0) &&
            current.codeHash != bytes32(0)) {
            return (true, bytes("Unauthorized proxy upgrade detected"));
        }

        return (false, bytes(""));
    }
}
