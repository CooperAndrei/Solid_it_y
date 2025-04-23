Easy

1- What is the difference between private, internal, public, and external functions?

Private: Only callable within the same contract.
Internal: Callable within the contract and derived contracts.
Public: Callable everywhere (internally & externally).
External: Only callable from outside the contract (not internally). 

2- Approximately, how large can a smart contract be? 

~24 KB (EIP-170 limit). Larger contracts may fail deployment.

3- What is the difference between create and create2? 

create: Address depends on sender + nonce.
create2: Address depends on sender, salt, and bytecode (predictable).

4- What major change with arithmetic happened with Solidity 0.8.0? 

Auto-reverts on overflow/underflow(no need for SafeMath).

5- What special CALL is required for proxies to work?
 
DELEGATECALL- preserves context, executes logic in proxy storage.

6- How do you calculate the dollar cost of an Ethereum transaction?

Gas Used × Gas Price (in gwei) × ETH/USD Price
 

7- What are the challenges of creating a random number on the blockchain? 

On-chain randomness is predictable(miners can manipulate). Use oracles (Chainlink VRF) or commit-reveal schemes.

8- What is the difference between a Dutch Auction and an English Auction? 
Dutch Auction: Price starts high, decreases over time (first taker wins).

9- What is the difference between transfer and transferFrom in ERC20?
 
transfer: Send tokens from sender’s balance.
transferFrom: Send tokens from an approved allowance (for delegated transfers).

10- Which is better to use for an address allowlist: a mapping or an array? Why? 
Mapping (better): O(1) lookup, cheaper gas. Arrays are O(n) for checks.

11- Why shouldn’t tx.origin be used for authentication? 
Vulnerable to phishing (intermediary contract can spoof the original sender). Use msg.sender instead.

12- What hash function does Ethereum primarily use? 

Keccak-256

13- How much is 1 gwei of Ether? 
1 gwei = 0.000000001 ETH (1e-9 ETH)

14- How much is 1 wei of Ether?

1 wei = 0.000000000000000001 ETH (1e-18 ETH)

15- What is the difference between assert and require?

    • require: Validates inputs/conditions, refunds gas (for errors).
    • assert: Checks internal invariants, consumes all gas (for bugs).

16 - What is a flash loan? 

Flash Loan: A loan borrowed and repaid in one transaction (no collateral if returned within the same block).

17- What is the check-effects-interaction pattern? 

Check-Effects-Interaction: A security pattern:
Check conditions → Update state → Interact with external contracts.
Why?Prevents reentrancy attacks (e.g., The DAO hack).

function withdraw() external {
    // CHECK: Validate conditions
    require(balances[msg.sender] > 0, "No funds");
    
    // EFFECTS: Update state **before** interaction
    uint amount = balances[msg.sender];
    balances[msg.sender] = 0;
    
    // INTERACTION: Call external contract
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}

Mistake:Doing interaction before state changes → reentrancy risk.

What is the minimum amount of Ether required to run a solo staking node? 
32

What is the difference between fallback and receive? 

receive(): Handles plain Ether transfers (no data).
fallback(): Executes when no function matches (or if data is sent).




receive() external payable {} // Handles plain ETH transfers  
fallback() external payable {} // Handles malformed calls  


What is reentrancy? 

An attack where a malicious contract re-calls a vulnerable function before its state updates.



Attack Flow:
    1. Attacker calls withdraw() in Victim Contract.
    2. Victim sends ETH before updating balance.
    3. Attacker’s fallback() re-calls withdraw() → drains funds.
Prevention:
    • Use CEI pattern.
    • Apply reentrancy guards (OpenZeppelin’s ReentrancyGuard).

What prevents infinite loops from running forever? 

Infinite Loop Prevention: Gas limits—transactions run out of gas and revert.
Ethereum blocks cap gas (~30M gas/block).

What is the difference between tx.origin and msg.sender? 

tx.origin: Original EOA (risky for auth).
msg.sender: Immediate caller (could be a contract).

How do you send Ether to a contract that does not have payable functions, or a receive or fallback? 

Sending Ether to Non-Payable Contracts: Impossible—requires payable, receive(), or fallback().

24- What is the difference between view and pure? 

view: Reads state (no gas cost off-chain).
pure: No state read/write (only computations).

25- What is the difference between transferFrom and safeTransferFrom in ERC721?

* safeTransferFrom: Checks if recipient is a contract and supports ERC721 (prevents lost tokens).
* TransferFrom: No recipient checks (riskier).

How can an ERC1155 token be made into a non-fungible token?
Mint a token with a supply of 1 (unique ID).
_mint(msg.sender, 123, 1, ""); // NFT (ID 123, only 1 exists)  
_mint(msg.sender, 456, 1000, ""); // Fungible (ID 456, 1000 copies)  

What is access control and why is it important?
Restricts contract functions to authorized users (e.g., owners), preventing unauthorized actions

What does a modifier do?
A reusable condition (e.g.,onlyOwner) applied to functions.

What is the largest value a uint256 can store?
2^256−1(a 78-digit number).

30- What is variable and fixed interest rate?
Variable: Changes based on market conditions.
Fixed: Remains constant for the loan term.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


Medium 

1-23

What is the difference between transfer and send? Why should they not be used?

transfer: Reverts on failure (gas limit 2300).
send: Returns false on failure (gas limit 2300).
Avoid both: Fixed gas limits can break integrations; use call instead.

What is a storage collision in a proxy contract? 

Occurs when proxy and implementation storage slots overlap, corrupting data. Use unstructured storage or EIP-1967 for safe slots.

What is the difference between abi.encode and abi.encodePacked? 

encode: Pads to 32 bytes, preserves types (safe for hashing).
encodePacked: Tightly packs (smaller, but can cause hash collisions).

uint8, uint32, uint64, uint128, uint256 are all valid uint sizes. Are there others?
Only powers of 8 

What changed with block.timestamp before and after proof of stake? 

PoS made it more accurate (12s slots vs. PoW’s ~13s).

What is frontrunning? 
Miners/validators exploit tx order (e.g., sandwich attacks). Mitigate with private mempools or commit-reveal.


What is a commit-reveal scheme and when would you use it? 
Two-phase: Commit (hash of secret + data), then reveal. Used for fair randomness or anti-frontrunning.


Under what circumstances could abi.encodePacked create a vulnerability? 

Hash collisions if dynamic types are mixed (e.g., encodePacked("AA", "BC") == encodePacked("AAB", "C")).


How does Ethereum determine the BASEFEE in EIP-1559? 

Adjusted per block based on network congestion (↑ if full, ↓ if empty). Burned, not paid to miners.


What is the difference between a cold read and a warm read?

Cold: First access (2100 gas). Warm: Subsequent access (100 gas).
 

How does an AMM price assets? 

Constant product formula: x * y = k (e.g., Uniswap). Price adjusts based on pool reserves.


What is a function selector clash in a proxy and how does it happen? 

Occurs if proxy and implementation have same function selector. Mitigate with Transparent Proxy (admin-only fallback).


What is the effect on gas of making a function payable? 

Saves ~20 gas by skipping isPayable check.

What is a signature replay attack? 

Reusing a signed tx on another chain/contract. Prevent with nonces or chain-specific signatures.


How would you design a game of rock-paper-scissors in a smart contract such that players cannot cheat? 
Commit phase: Players submit hash(choice + secret).
Reveal phase: Submit choice and secret.
Verify hashes match and decide winner.


What is the free memory pointer and where is it stored? 

Tracks next free memory slot. Stored at 0x40 in Solidity.

What function modifiers are valid for interfaces? 

Only view, pure, and payable are valid.

What is the difference between memory and calldata in a function argument? 

memory: Modifiable copy (costs gas).
calldata: Read-only reference (cheaper for external calls).


Describe the three types of storage gas costs for writes. 

Zero → Non-zero: 20k gas.
Non-zero → Non-zero: 5k gas.
Non-zero → Zero: Refund 4.8k gas.

Why shouldn’t upgradeable contracts use the constructor? 
Constructor code is not inherited. Use initializer functions instead

What is the difference between UUPS and the Transparent Upgradeable Proxy pattern? 

UUPS: Upgrade logic in implementation (cheaper).
Transparent: Upgrade logic in proxy (safer, avoids selector clashes).


If a contract delegatecalls an empty address or an implementation that was previously self-destructed, what happens? 
delegatecall to Empty/Self-Destructed Address:
    • delegatecall: Fails silently (no state change).
    • call: Returns false (no revert).

What if it is a low-level call instead of a delegatecall? 


What danger do ERC777 tokens pose? 

Hooks allow reentrancy attacks (e.g., DAO hack).


According to the solidity style guide, how should functions be ordered? 

Constructor
Receive/fallback
External
Public
Internal
Private
CREPIP

According to the solidity style guide, how should function modifiers be ordered?

Place modifiers after visibility (e.g., external payable).

24-33

24- What is a bonding curve? 

A mathematical curve that defines the price of a token based on its supply (e.g., buy price increases as supply grows). Used in token minting/burning mechanisms (e.g.,Curve Finance pools).

25- How does _safeMint differ from _mint in the OpenZeppelin ERC721 implementation? 

*  _mint: Basic minting without checks.
*  _safeMint: Calls onERC721Received on the recipient if it’s a contract, preventing tokens from being locked in non-ERC721-aware contracts. Reverts if the recipient doesn’t handle the token.

What keywords are provided in Solidity to measure time? 

* block.timestamp (current epoch time in seconds).
* block.number (block height, approximate time via average block time).

What is a sandwich attack? 

A MEV attack where a bot front-runs a victim’s trade (buying before them) and back-runs it (selling after), profiting from the victim’s price impact.

If a delegatecall is made to a function that reverts, what does the delegatecall do? (check 36 as well)

The delegatecall returns false (instead of bubbling up the revert), allowing the caller to handle it. The proxy’s state changes before the revert are kept. 

What is a gas efficient alternative to multiplying and dividing by a power of two?

Use bit-shifting:
      * Multiply: x << n (equivalent to x*2n).
      * Divide: x >> n (equivalent to x÷2n).


How large a uint can be packed with an address in one slot? 

address: 20 bytes.
      Slot size: 32 bytes.
      So the Max uint: uint96 (12 bytes), since 20+12=32.


Which operations give a partial refund of gas? 

* SSTORE (refund for clearing storage, e.g., setting non-zero → zero).
* SELFDESTRUCT (refund for deleting a contract).
(Note: Refunds were capped after EIP-3529.)
What is ERC165 used for? 

Standard for runtime interface detection. Contracts declare supported interfaces (e.g., supportsInterface(0x80ac58cd) for ERC721).

If a proxy makes a delegatecall to A, and A does address(this).balance, whose balance is returned, the proxy’s or A? 

The proxy’s balance (since delegatecall preserves msg.sender, address(this), and storage context).

What is a slippage parameter useful for? 

Sets the minimum received (or maximum spent) tolerance for trades, protecting against price swings (e.g., Uniswap’s amountOutMin).

What does ERC721A do to reduce mint costs? What is the tradeoff? 

Optimization: Batch mints (e.g., 10 NFTs) share a single storage write for balances/owners.
Tradeoff: Higher gas for transfers (must iterate to find ownership data).

Why doesn’t Solidity support floating point arithmetic?

* Determinism: Floating-point rounding can vary across platforms (bad for consensus).
* Gas costs: Complex to implement securely.
* Alternatives: Use fixed-point (e.g., UD60x18) or scaled integers (e.g., 1e18 = 1.0).

Medium 34-43


34 - What is TWAP? 

(Time-Weighted Average Price) is an average price of an asset over a specified time period, commonly used in DeFi to reduce price manipulation risks in oracles.

35- How does Compound Finance calculate utilization? 

Utilization rate in Compound is calculated as:
Utilization=Total Borrows / (Total Cash+Total Borrows) 
It measures how much of the supplied liquidity is being borrowed.


36 If a delegatecall is made to a function that reads from an immutable variable, what will the value be? 

The value will be incorrect (likely 0 or garbage). Delegatecall uses the storage context of the caller, but immutable variables are inlined at compile time in the callee’s code.


What is a fee-on-transfer token? 

A token that deducts a fee on transfers (e.g.,STAKE, USDT on some chains). The actual received amount is less than the sent amount, causing issues in contracts that assume full balance updates.

What is a rebasing token? 

A token (e.g.,AMPL,stETH) where balances automatically adjust (rebase) to reflect inflation/deflation, without explicit transfers. Total supply changes, but holders’ proportional ownership stays the same.

CAN AN NFT BE REBASE TOKEN

In what year will a timestamp stored in a uint32 overflow? 
2106
A uint32 overflows at 2^32 seconds (~136 years). Unix time started in 1970, so overflow occurs in 2106.


What is LTV in the context of DeFi? 

Loan-to-Value (LTV) is the maximum borrowing limit against collateral (e.g., 70% LTV means you can borrow up to 70% of the collateral’s value).

What are aTokens and cTokens in the context of Compound Finance and AAVE?

* aTokens (AAVE): Minted 1:1 when depositing and burn when withdrawing; balances increase with interest in real-time.
* cTokens(Compound): Interest-accruing tokens representing a claim on underlying assets (exchange rate increases over time).


Describe how to use a lending protocol to go leveraged long or leveraged short on an asset. 

  * Leveraged Long:
        1. Deposit collateral (e.g., ETH).
        2.  Borrow stablecoins, swap to more ETH, and redeposit. Repeat.
           
      * Leveraged Short:
        1. Deposit collateral (e.g., ETH).
        2. Borrow ETH, sell it for stablecoins. If ETH price drops, buy back cheaper ETH to repay.


What is a perpetual protocol?

A derivatives protocol (e.g., Perpetual Protocol, dYdX) offering perpetual contracts (no expiry) with leverage, using funding rates to peg prices to the underlying asset.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
Hard

How does fixed point arithmetic represent numbers? 
Fixed-Point Arithmetic
Represents decimals using integers (e.g., 1.23 as 123 with implied /100). No native support in Solidity—libraries (e.g., PRBMath) handle scaling.


What is an ERC20 approval frontrunning attack? 
When a user approves X tokens, an attacker replaces it with a smaller approval via higher gas, then steals the difference. Mitigate with:
approve(0, amount); // Reset first  
approve(spender, amount);  

What opcode accomplishes address(this).balance? 

SELFBALANCE (EIP-1884) or BALANCE (pre-EIP-1884).

How many arguments can a solidity event have? 

Up to 3 indexed (for efficient filtering) and unlimited non-indexed.

What is an anonymous Solidity event? 

Omits the event signature in logs (saves gas), but cannot be filtered by name.

Under what circumstances can a function receive a mapping as an argument? 
Only in internal/private functions, or via storage reference (not memory/calldata).

What is an inflation attack in ERC4626?

An attacker donates tiny shares to inflate the vault’s TVL, diluting other users. Mitigate with:
    • Minimum deposits.
    • Virtual shares (Uniswap V2-style).


How many storage slots does this use? uint64[] x = [1,2,3,4,5]? Does it differ from memory?
 
Storage: 1 slot for length + 3 slots (packed: 2 * uint64 per slot).
Memory: No packing—5 slots.


Prior to the Shanghai upgrade, under what circumstances is returndatasize() more efficient than PUSH 0?

returndatasize() is cheaper when return data exists (avoids zero-pushing).

Why does the compiler insert the INVALID op code into Solidity contracts? 

Compiler inserts it for:
    • Unreachable code.
    • Function selector fallback.


What is the difference between how a custom error and a require with error string is encoded at the EVM level? 

Custom Error: 4-byte selector + ABI-encoded args (cheaper).
require: Full string (expensive, logs as revert reason).


1hat What is the kink parameter in the Compound DeFi formula? 
In the interest rate model:
    • Kink: Utilization rate where slope changes (e.g., 80%).


1ow How can the name of a function affect its gas cost, if at all? 
Longer names increase deployment cost (stored in bytecode), but runtime cost is unaffected (uses 4-byte selector).

What is a common vulnerability with ecrecover? 

Malleable signatures:s must be ≤ n/2 (EIP-2).
Zero address return: Check address != 0.


What is the difference between an optimistic rollup and a zk-rollup? 

Optimistic: Fraud proofs (7-day challenge window).
ZK: Validity proofs (instant finality, heavier computation).


How does EIP1967 pick the storage slots, how many are there, and what do they represent? 
3 Slots:
        ◦ 0x360894...: Implementation address.
        ◦ 0xb531276...: Beacon address.
        ◦ 0xc5f16f0...: Admin address.

How much is one Sazbo of ether? 

1 Szabo = 1e12 wei = 0.000001 ETH (1 µETH).  

What can delegatecall be used for besides use in a proxy? 

Library calls e.g., Using SafeMath for uint.
State injection (execute logic in another contract’s context).

Under what circumstances would a smart contract that works on Etheruem not work on Polygon or Optimism? (Assume no dependencies on external contracts)
Gas opcodes e.g.,GASPRICE.
Block properties e.g. block.number
Chain-specific precompiles.

How can a smart contract change its bytecode without changing its address?

SELFDESTRUCT + CREATE2 re-deploy to same address.


What is the danger of putting msg.value inside of a loop? 

Reentrancy: Each iteration reuses msg.value.
Overpayment: Use a local variable to track remaining value.
escribe the calldata of a function that takes a dynamic length array of uint128 when uint128[1,2,3,4] is passed as an argument 
Calldata for uint128[1,2,3,4]
    • Layout: Offset (0x20) → Length (4) → Packed values (0x0001...0004).


Why is strict inequality comparisons more gas efficient than ≤ or ≥? What extra opcode(s) are added? 

Strict Inequality Gas Efficiency
</> use LT/GT (1 opcode).<=/>= add ISZERO (extra opcode).

If a proxy calls an implementation, and the implementation self-destructs in the function that gets called, what happens? 
Proxy + Selfdestruct
    • Proxy survives: delegatecall preserves proxy’s state.
    • Implementation dies: Future calls fail until re-deployed.

What is the relationship between variable scope and stack depth? 

Deep scopes (e.g., nested loops) risk stack too deep (max 16 slots).
What is an access list transaction? 
Access List Transaction
Pre-pays for storage accesses (EIP-2930), reducing cold access costs.

How can you halt an execution with the mload opcode? 
Halt Execution with mload
    • Mload(0) → Reads from scratch space (safe).
    • mload(<invalid>) → Reverts (out-of-bounds).
      
What is a beacon in the context of proxies?
Beacon in Proxies
    • Central contract holding the implementation address. Proxies delegatecall the beacon for upgrades.


Why is it necessary to take a snapshot of balances before conducting a governance vote? 

To prevent vote manipulation (e.g., buying/selling tokens mid-vote). Snapshots lock balances at a specific block.

How can a transaction be executed without a user paying for gas? 
Gasless Transaction Execution
    • Meta Transactions: Relayer pays gas (ERC-2771, Gas Station Network).
      
    • Sponsored Transactions: Protocols subsidize gas (e.g., Biconomy).

In solidity, without assembly, how do you get the function selector of the calldata?

Function selector wo assembly
bytes4 selector = bytes4(msg.data[:4]);  
 
How is an Ethereum address derived? 

EOA: keccak256(publicKey)[12:] (last 20 bytes).
Contract: keccak256(creator + nonce)[12:].


What is the metaproxy standard?

A minimal proxy factory standard for cheap clone deployments.

If a try catch makes a call to a contract that does not revert, but a revert happens inside the try block, what happens? 

Try-Catch Behavior on Revert
    • Revert inside try: Catches the error, executes catch block.
    • No revert in call: Continues normally.

If a user calls a proxy makes a delegatecall to A, and A makes a regular call to B, from A’s perspective, who is msg.sender? from B’s perspective, who is msg.sender? From the proxy’s perspective, who is msg.sender? 
msg.sender in Nested Calls (Proxy → A → B)
    • A’s perspective: msg.sender = proxy.
    • B’s perspective: msg.sender = A (not the original user).
    • Proxy’s perspective: msg.sender = user.

Under what circumstances do vanity addresses (leading zero addresses) save gas? 

Leading zeros reduce gas for SSTORE (cold→warm if slot 0x00...is reused).

Why do a significant number of contract bytecodes begin with 6080604052? 
What does that bytecode sequence do? 

60 80: PUSH1 0x80 (free memory pointer).
60 40: PUSH1 0x40 (memory store).
52: MSTORE (sets free memory pointer).

How does Uniswap V3 determine the boundaries of liquidity intervals?

Tick spacing: Liquidity is concentrated between lowerTick and upperTick (set by LP). 
What is the risk-free rate? 

Theoretical return on zero-risk assets (e.g., US Treasuries). Used in DeFi for pricing

When a contract calls another call via call, delegatecall, or staticcall, how is information passed between them? 

Call/Delegatecall/Staticcall Data Passing
    • call/staticcall: msg.data forwarded.
    • delegatecall: Preserves msg.sender and msg.value

What is the difference between bytes and bytes1[]? 

bytes: Packed dynamically (cheaper).
bytes1[]: Unpacked (each element in a new slot).

What is the most amount of leverage that can be achieved in a borrow-swap-supply-collateral loop if the LTV is 75%? What about other LTV limits? 

* LTV 75%: Max leverage = 1 / (1 - LTV) = 4x.
* General formula: 1 / (1 - LTV).

How does Curve StableSwap achieve concentrated liquidity? 

Uses invariant amplification to reduce slippage for stablecoins.

What quirks does the Tether stablecoin contract have? 

Centralized freezing.
Blacklisting.
No decimals() in early versions.

What is the smallest uint that will store 1 million? 1 billion? 1 trillion? 1 quadrillion? 

1M: uint20 (covers up to ~1.05M).
1B: uint30 (covers up to ~1.07B).
1T: uint40  (covers up to ~1.1T).
1Q: uint50 covers up to ~1.13Q).

What danger to uninitialized UUPS logic contracts pose?

Attackers can self-destruct or hijack the proxy if logic contract is uninitialized.

What is the difference (if any) between what a contract returns if a divide-by-zero happens in Soliidty or if a dividye-by-zero happens in Yul? 
Divide-by-Zero in Solidity vs Yul
    • Solidity: Reverts.
    • Yul: Returns 0 (unless checked manually).


Why can’t .push() be used to append to an array in memory?

Memory arrays have fixed size; use index assignment instead:
uint[] memory arr = new uint[](3);  
arr[0] = 1; // No .push()  

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Advance

What addresses to the ethereum precompiles live at? 

Precompiles live at addresses 0x01 to 0x09 (e.g.,0x01= ecrecover, 0x05 = modExp).

Describe what “liquidity” is in the context of Uniswap V2 and Uniswap V3. 

Uniswap V2: Liquidity is uniformly distributed across the entire price curve (x * y = k).
    • Uniswap V3: Liquidity is concentrated in custom price ranges (ticks), improving capital efficiency.


If a delegatecall is made to a contract that makes a delegatecall to another contract, who is msg.sender in the proxy, the first contract, and the second contract? 

Proxy: Original msg.sender (user).
    • First contract: Proxy’s address.
    • Second contract: First contract’s address.
(Each delegatecall preserves the original msg.sender but executes in the caller’s context.)


What is the difference between how a uint64 and uint256 are abi-encoded in calldata? 
ABI Encoding: uint64 vs uint256 in Calldata
    • uint64: Right-padded to 32 bytes (e.g.,0x...00000042).
    • uint256: Full 32 bytes (no padding).

What is read-only reentrancy? 

A contract reads stale state during a reentrant call (e.g., checking balances mid-transaction). Common in lending protocols.

What are the security considerations of reading a (memory) bytes array from an untrusted smart contract call? 

Security of Reading Untrusted bytes from Memory
    • Danger: Malicious contract could return garbage data, causing OOG or unexpected behavior.
    • Mitigation: Validate length + content
      
How does the EVM price memory usage? 

EVM Memory Pricing
    • First 724 bytes: Linear gas cost (3 gas/word).
    • Expansion cost: Quadratic beyond 724 bytes.
      

If you deploy an empty Solidity contract, what bytecode will be present on the blockchain, if any? 
Bytecode of an Empty Solidity Contract
    • Minimal runtime bytecode:0x60806040526000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680635c60da1b1461003a575b600080fd5b341561004557600080fd5b61004d610067565b60405180826000191660001916815260200191505060405180910390f35b60008090509056fea165627a7a72305820...
(Includes constructor logic + minimal metadata.)





What is stored in the metadata section of a smart contract? 

Smart Contract Metadata
Stores compiler version, source code hash, ABI, and IPFS/SWARM references (appended to bytecode).

What is the uncle-block attack from an MEV perspective? 

Uncle-Block MEV Attack
    • Miners reorg blocks to extract MEV from uncle blocks (obsolete but high-reward transactions).


How do you conduct a signature malleability attack? 

Signature Malleability Attack
    • Exploiting ECDSA’s s-value symmetry (fixed by enforcing s ≤ n/2 per EIP-2).


Under what circumstances do addresses with leading zeros save gas and why? 
Gas Savings with Leading-Zero Addresses
    • Saves gaswhen writing to storage slot 0x00...(cold→warm transition is cheaper).

What is the difference between payable(msg.sender).call{value: value}("") and msg.sender.call{value: value}("")? 

payable(msg.sender).call{value: value}("") vs msg.sender.call{value: value}("")
    • No difference: Both compile to the same opcodes. Payable() is a type-checker hint.


1How many storage slots does a string take up? 
Storage Slots for string
    • 1 slot for length + 1 slot per 32 bytes of data.


How does the --via-ir functionality in the Solidity compiler work? 

--via-ir in Solidity Compiler
    • Uses Intermediate Representation (IR) for optimizations (better gas efficiency, slower compilation).


Are function modifiers called from right to left or left to right, or is it non-deterministic? 
Function Modifier Order
    • Left-to-right (e.g., @modA @modB executes modA first).


If you do a delegatecall to a contract and the opcode CODESIZE executes, which contract size will be returned? 

CODESIZE in delegatecall
    • Returns target contract’s code size (not the proxy’s).

Why is it important to ECDSA sign a hash rather than an arbitrary bytes32? 
ECDSA Signing a Hash (Not Raw bytes32)
    • Prevents signature replay across different contexts (e.g., signing keccak256(abi.encodePacked(...))).

Describe how symbolic manipulation testing works. 
Symbolic Manipulation Testing
    • Tools (e.g.,Manticore) explore all possible execution paths by treating inputs as symbolic variables.


What is the most efficient way to copy regions of memory? 
Most Efficient Memory Copy
    • Yul assembly: calldatacopy/mcopy (EIP-5656) for low-level control.


How can you validate on-chain that another smart contract emitted an event, without using an oracle? 

Validate Event Emission Without Oracle
    • Use eth_getLogs or third-party contract’s event history (if indexed).

When selfdestruct is called, at what point is the Ether transferred? At what point is the smart contract’s bytecode erased?

Selfdestruct Timing
    • Ether transferred immediately.
    • Bytecode erased at end of transaction (not mid-execution).

Under what conditions does the Openzeppelin Proxy.sol overwrite the free memory pointer? Why is it safe to do this? 
OpenZeppelin Proxy.sol Free Memory Pointer Overwrite
    • Conditions: Overwrites the free memory pointer (0x40) during delegatecall setup.
    • Safety: The proxy preserves the original value after execution, ensuring no memory corruption.

Why did Solidity deprecate the “years” keyword?

Reason: Ambiguity (leap years, inconsistent time units). Use days or explicit timestamps instead. 

What does the verbatim keyword do, and where can it be used? 
verbatim Keyword
    • Purpose: Inline arbitrary bytecode in Yul (bypassing Solidity checks).
    • Usage: Only in Yul assembly, for low-level optimizations.

How much gas can be forwarded in a call to another smart contract? 
Gas Forwarding in Smart Contract Calls
    • All remaining gas is forwarded by default (use gas() to limit).
    • Exception: transfer/send cap at 2300 gas.

What does an int256 variable that stores -1 look like in hex? 
 
0xff...ff (all bits set to 1).

What is the use of the signextend opcode? 

signextend Opcode Purpose: 
	Extends the sign bit of a signed integer (e.g., 0xff → 0xffff...).


Why do negative numbers in calldata cost more gas? 

Extra padding for sign extension increases calldata size (higher gas).


What is a zk-friendly hash function and how does it differ from a non-zk-friendly hash function? 

ZK-Friendly Hash Function
    • Example: Poseidon, MiMC.
    • Difference: Optimized for arithmetic circuits (fewer constraints vs. Keccak).
      
What does a metaproxy do? 

Minimal proxy factory (EIP-3448) for cheap clone deployments.

What is a nullifier in the context of zero knowledge, and what is it used for? 

Purpose: Prevents double-spending in ZK systems (e.g., Tornado Cash).
Mechanism: Unique hash per action, published on-chain.

What is SECP256K1? 
SECP256K1 - Elliptic curve used in Ethereum for ECDSA (key pairs, signatures).

Why shouldn’t you get price from slot0 in Uniswap V3? 

Risk: Manipulable (MEV, flash loans). Use TWAP oracles instead.


Describe how to compute the 9th root of a number on-chain in Solidity. 
Compute 9th Root On-Chain
    • Method: Binary search + approximation (e.g., Newton-Raphson).
    • Gas-heavy: Avoid unless necessary.

What is the danger of using return in assembly out of a Solidity function that has a modifier? 
Danger of return in Assembly with Modifiers
    • Bypasses checks: Modifiers may not execute fully, breaking invariants.

Without using the % operator, how can you determine if a number is even or odd?

bool isEven = (n & 1 == 0);  	

What does codesize() return if called within the constructor? What about outside the constructor?
codesize() in Constructor vs. Outside
    • Constructor: Returns runtime bytecode size (deployment code excluded).
    • Outside: Returns full deployed bytecode size.

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


extra
What is a Salt?
A salt is a random or unique value added to input data (like passwords) before hashing to enhance security. Its primary purpose is to defend against precomputed attacks (e.g., rainbow tables) and ensure that identical inputs produce different hashes.
How does the EVM handle stack underflows/overflows, and what happens if one occurs?
Stack underflow: Occurs when popping from an empty stack → Halts executio  (reverts).
Stack overflow: Occurs when pushing beyond 1024 slots → Reverts with "stack too deep".
Example: Infinite recursion causes stack overflow.

What is the purpose of the EXTCODEHASH opcode, and when would you use it?

Returns the keccak256 hash of a contract’s bytecode.
Use cases:
        ◦ Verify if a contract is deployed (hash != 0).
        ◦ Detect code changes (e.g., upgradeable contracts).

Why does SSTORE cost more gas on the first write compared to subsequent writes?
First write (zero → non-zero): 22,100 gas (cold access).
Subsequent writes: 5,000 gas (warm access).
Reason: Initial write modifies storage trie (expensive), while updates are cheaper.

What is "gas token" (e.g., GST2/CHI), and how does it work to save gas?
Tokens that exploit SSTORE gas refunds (pre-1559).
Mechanism: Mint (store non-zero) when gas is cheap, burn (set to zero) when gas is expensive for a refund.

How does CREATE2 prevent address collisions when combined with SELFDESTRUCT?
CREATE2 derives addresses from (sender, salt, bytecode).
Even if a contract selfdestructs, reusing the same (sender, salt, bytecode) reproduces the same address.

What is a "phantom function" attack in proxy contracts?

When a proxy lacks a function, but the implementation has it → Attacker can invoke unintended logic.
Fix: Use TransparentProxy (admin-only fallback).

How can a malicious contract exploit extcodesize checks to bypass security?

A contract’s extcodesize is 0 during constructor execution → Malicious contracts can fake EOA status.

What is a "storage collision" in the context of diamond proxies (EIP-2535)?

Two facets use the same storage slot → Corrupts data.
Fix: Use DiamondStorage (structs with unique slots).


Why is block.timestamp considered a weak source of randomness, even in PoS?
Validators can slightly influence timestamps → Predictable in PoS (unlike PoW’s miner voting).

How can a reentrancy attack occur without using call.value()?
Via ERC777 hooks or onERC721Received → Callback re-enters before state updates.

What is a "beacon proxy," and how does it differ from UUPS/Transparent proxies?
Proxies fetch implementation address from a beacon contract → Single upgrade point for many proxies.

Why can’t you delegatecall to a contract that uses selfdestruct?
selfdestruct kills the caller’s context (proxy), not the target.


How does the "diamond pattern" (EIP-2535) resolve function selector clashes?
Facets register functions in a central lookup table → No overlap.

What happens if a proxy’s implementation contract has a constructor with arguments?
Problem: Constructors are not inherited.
Fix: Use an initialize function with initializer modifier.

Why is initializer a safer alternative to constructors in upgradeable contracts?
Ensures one-time initialization (prevents reinitialization attacks).


