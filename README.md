# Multisig Anomaly Trap

A Drosera trap that detects compromised admin key attacks by monitoring ownership changes, timelock bypass attempts, and unauthorized proxy upgrades on protected protocols.

## Real-World Hack: Radiant Capital ($50M Loss)

In October 2024, Radiant Capital was exploited for approximately **$50 million** when attackers compromised the private keys of three out of eleven multisig signers. The attackers used the compromised keys to push through a malicious contract upgrade that replaced the protocol's lending pool implementation with a backdoored version containing a `transferFrom` function that drained all user-approved funds. The entire attack -- from the malicious proposal to the fund extraction -- happened within minutes, far too fast for human governance monitoring to react.

This attack pattern is increasingly common. The Ronin Bridge hack ($624M, March 2022) also exploited compromised validator keys, and the Harmony Bridge hack ($100M, June 2022) resulted from stolen multisig keys. In all cases, the attackers bypassed or manipulated governance mechanisms to gain control of the protocol's upgrade path.

## Attack Vector: Admin Key Compromise

Admin key compromise attacks follow this pattern:

1. **Attacker obtains private keys** -- through phishing, malware, social engineering, or insider threats. They need enough keys to meet the multisig threshold.
2. **Attacker submits a malicious proposal** -- typically a proxy upgrade that replaces the protocol's implementation contract with a backdoored version.
3. **Attacker bypasses or weakens governance safeguards** -- reducing timelock delays to zero, or executing the upgrade before the timelock period expires.
4. **Malicious code is deployed** -- the proxy now points to attacker-controlled logic that can drain funds, mint unbacked tokens, or transfer ownership.
5. **Funds are extracted** -- the attacker calls the backdoored functions to drain the protocol.

The detectable signals: **ownership changes**, **timelock delay reductions**, and **contract code hash changes** (proxy upgrades).

## How the Trap Works

### Data Collection (`collect()`)

Every block, the trap reads three pieces of state from the monitored protocol (`0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2`):

- **`currentOwner`** -- The current owner address from `IOwnable.owner()`
- **`timelockDelay`** -- The minimum delay enforced by the timelock controller from `ITimelockController.getMinDelay()`
- **`codeHash`** -- The `codehash` of the monitored contract (detects proxy implementation changes)
- **`blockNumber`** -- The current block number

If any call reverts, the corresponding value defaults to zero/null so the trap avoids false positives.

### Trigger Logic (`shouldRespond()`)

The trap compares current and previous block data and triggers on four independent conditions:

**Condition 1: Ownership Change**

```
TRIGGER if current_owner != previous_owner
         AND neither is address(0)
```

Any ownership transfer is a critical governance event that warrants immediate investigation.

**Condition 2: Timelock Bypass (Delay Set to Zero)**

```
TRIGGER if previous_timelockDelay > 0
         AND current_timelockDelay == 0
```

Setting the timelock delay to zero removes all governance protections and is the most direct indicator of an admin key compromise.

**Condition 3: Timelock Weakening (Delay Reduced > 50%)**

```
TRIGGER if previous_timelockDelay > 0
         AND current_timelockDelay < previous_timelockDelay / 2
```

A significant reduction in timelock delay, even if not to zero, suggests an attacker is gradually undermining governance safeguards.

**Condition 4: Proxy Upgrade (Code Hash Change)**

```
TRIGGER if current_codeHash != previous_codeHash
         AND neither is bytes32(0)
```

A change in the contract's code hash indicates that the proxy implementation was upgraded. Unauthorized upgrades are the primary mechanism used in admin key compromise attacks.

## Threshold Values

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Ownership change | Any change | Ownership transfers are rare governance events. Any unexpected change is critical. |
| Timelock delay = 0 | Zero delay | A zero timelock delay means governance protections are completely removed. This should never happen in a healthy protocol. |
| Timelock weakening | > 50% reduction | Legitimate timelock adjustments are typically small. A 50%+ reduction signals an attacker weakening defenses. |
| Code hash change | Any change | Proxy upgrades are planned events. An unexpected code hash change indicates a potentially malicious upgrade. |
| `block_sample_size` | 10 | Captures changes over a 10-block window, providing enough context to detect multi-step governance attacks. |

## Configuration (`drosera.toml`)

```toml
ethereum_rpc = "https://ethereum-hoodi-rpc.publicnode.com"
drosera_rpc = "https://relay.hoodi.drosera.io"
eth_chain_id = 560048
drosera_address = "0x91cB447BaFc6e0EA0F4Fe056F5a9b1F14bb06e5D"

[traps.multisig_anomaly_trap]
path = "out/MultisigAnomalyTrap.sol/MultisigAnomalyTrap.json"
response_contract = "0x0000000000000000000000000000000000000000"
response_function = "emergencyPause()"
cooldown_period_blocks = 33
min_number_of_operators = 1
max_number_of_operators = 2
block_sample_size = 10
private_trap = false
whitelist = []
```

| Field | Description |
|-------|-------------|
| `ethereum_rpc` | RPC endpoint for the Ethereum chain being monitored (Hoodi testnet) |
| `drosera_rpc` | RPC endpoint for the Drosera relay network |
| `eth_chain_id` | Chain ID of the target network |
| `drosera_address` | Address of the Drosera protocol contract |
| `path` | Path to the compiled trap artifact (produced by `forge build`) |
| `response_contract` | Address of the contract to call when the trap triggers (set to zero address as placeholder) |
| `response_function` | Function signature to call on the response contract |
| `cooldown_period_blocks` | Minimum blocks between consecutive responses (prevents spam) |
| `min_number_of_operators` | Minimum Drosera operators required to reach consensus |
| `max_number_of_operators` | Maximum operators that can participate |
| `block_sample_size` | Number of consecutive blocks to collect data for |
| `private_trap` | Whether this trap is restricted to whitelisted operators |

## Architecture

```
+---------------------------------------------+
|         Monitored Protocol                   |
|         0x87870Bca3F3fD6335C3F...            |
+----------+----------+-----------+------------+
           |          |           |
  owner()  | getMinDelay()  codehash
           |          |           |
           v          v           v
+----------+----------+-----------+------------+
|            MultisigAnomalyTrap               |
|                                              |
|  collect():                                  |
|  - currentOwner    (who controls protocol?)  |
|  - timelockDelay   (is governance intact?)   |
|  - codeHash        (was proxy upgraded?)     |
|  - blockNumber                               |
+----------------------+-----------------------+
                       |
                       v
+----------------------+-----------------------+
|           shouldRespond()                    |
|                                              |
|  Compare blocks:                             |
|  - Owner changed?             --> TRIGGER    |
|  - Timelock set to 0?         --> TRIGGER    |
|  - Timelock reduced > 50%?    --> TRIGGER    |
|  - Code hash changed?         --> TRIGGER    |
+----------------------+-----------------------+
                       |
                       | if triggered
                       v
            +----------+----------+
            |  Response Contract   |
            |  emergencyPause()    |
            +---------------------+
```

## Build

```bash
npm install && forge build
```

## Test

```bash
forge test
```

## Dry Run

```bash
drosera dryrun
```

## Deploy

```bash
export DROSERA_PRIVATE_KEY=<your-private-key>
drosera apply
```

## License

MIT
