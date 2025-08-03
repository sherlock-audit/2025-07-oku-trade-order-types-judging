# Issue M-1: Time-sensitive DoS of the `performUpKeep()` function due to incorrect index of the order 

Source: https://github.com/sherlock-audit/2025-07-oku-trade-order-types-judging/issues/69 

## Found by 
BZ, ZeroEx, algiz, bulgari, codertjay, curly11, kimnoic, kingNull, tedox

### Summary
When an order is filled, the system verifies whether the order ID retrieved from a `dataset` at a specified index matches the provided order ID. Once the order is successfully filled, it is removed from the `dataset`, and the index of the last order in the `dataset` is updated to the index of the removed one. However, this process can lead to a vulnerability where the last order may not be filled in time due to the altered index and users can face loss of funds.

### Root Cause
In the `performUpkeep()` function, the order ID is retrieved from the the `dataset` using a specified index at [L150](https://github.com/sherlock-audit/2025-07-oku-trade-order-types/blob/0c17cd6ff7dc313b7ddebe6811bacffe4de43756/oku-custom-order-types/contracts/automatedTrigger/Bracket.sol#L150).
At [L151](https://github.com/sherlock-audit/2025-07-oku-trade-order-types/blob/0c17cd6ff7dc313b7ddebe6811bacffe4de43756/oku-custom-order-types/contracts/automatedTrigger/Bracket.sol#L151), it checks if the retrieved order ID matches the provided order ID.
After filling the order, the order ID is removed from the dataset, which results in the index of the last element being updated to the index of the removed order.
```solidity
    function performUpkeep(
        bytes calldata performData
    ) external override nonReentrant whenNotPaused {
        MasterUpkeepData memory data = abi.decode(
            performData,
            (MasterUpkeepData)
        );
@> 150  uint96 orderIdFromSet = uint96(dataSet.at(data.pendingOrderIdx));
@> 151  require(orderIdFromSet == data.orderId, "Order Fill Mismatch");
        ...
        //handle accounting
        //remove from pending dataSet
@> 181  require(dataSet.remove(order.orderId), "order not active");
```
This issue occurs not only in `Bracket` but also in `StopLimit` and `OracleLess`.

### Internal pre-conditions
N/A

### External pre-conditions
The last order in the `dataset` is going to be filled right after another order in the `dataset` is filled.

### Attack Path
N/A

### Impact
The order can't be filled in time due to DoS and users can face loss of funds.
Since filling order is a time-sensitive function, this qualifies as Medium Severity.
As the length of `dataset` is fixed as `150` in both `Bracket` and `StopLimit`, this occurs frequently.

### PoC
Let's consider the follwing scenario.

- There are 30 orders in the `dataset`.
- Both the 10th and 30th orders are triggered because they have the same stop price.
- Alice calls the `performUpKeep()` function to fill the 10th order.
- Bob also calls the `performUpKeep()` function to fill the 30th order.
- Both Alice's and Bob's transactions are included in the same block, with Alice's transaction being executed before Bob's.
- After Alice's transaction is executed, the index of Bob's order is updated from the 30th to the 10th.
- Bob's transaction is reverted due to the changed index.

### Mitigation
It is recommended to modify the code as follows:
```diff
-       uint96 orderIdFromSet = uint96(dataSet.at(data.pendingOrderIdx));
-       require(orderIdFromSet == data.orderId, "Order Fill Mismatch");
+       require(dataSet.contains(data.orderId), "order not active");
        Order memory order = orders[data.orderId];
```

# Issue M-2: Users lose more than 0.01% of their principal due to the precision loss in the exchange rate 

Source: https://github.com/sherlock-audit/2025-07-oku-trade-order-types-judging/issues/103 

## Found by 
bulgari, curly11

### Summary
When a user wants to swap one token for another, the system retrieves the prices of the tokens from the oracle. It then calculates the exchange rate for the `tokenIn/tokenOut` pair, with the decimal precision set to `1e8`. This level of precision is insufficient for high-value tokens like WBTC. Consequently, users may lose more than 0.1% of their funds, even though they set an appropriate slippage basis points.

### Root Cause
When an order is filled, the system first calculates the minimum amount that a user should receive based on the slippage set by the user at [L634](https://github.com/sherlock-audit/2025-07-oku-trade-order-types/blob/0c17cd6ff7dc313b7ddebe6811bacffe4de43756/oku-custom-order-types/contracts/automatedTrigger/Bracket.sol#L634). It then checks if this minimum amount is greater than the swapped amount out at [L645](https://github.com/sherlock-audit/2025-07-oku-trade-order-types/blob/0c17cd6ff7dc313b7ddebe6811bacffe4de43756/oku-custom-order-types/contracts/automatedTrigger/Bracket.sol#L645).

```solidity
@> 634      uint256 baseMinAmount = MASTER.getMinAmountReceived(
                amountIn,
                tokenIn,
                tokenOut,
                bips
            );
            uint256 feeAdjustedMinAmount = getMinAmountReceivedAfterFee( // @audit-info this is not important, so I skipped in the report
                baseMinAmount,
                feeBips
            );
            require(
@> 645          finalTokenOut - initialTokenOut >= feeAdjustedMinAmount,
                "Too Little Received"
            );
```
 The minimum amount received is calculated using the `AutomationMaster.getMinAmountReceived()` function, which incorporates the exchange rate in its calculation. 
```solidity
    function getMinAmountReceived(
        uint256 exchangeRate = _getExchangeRate(tokenIn, tokenOut);
        ...
        } else if (decimalIn < decimalOut) {
            fairAmountOut =
                (amountIn * exchangeRate * (10 ** (decimalOut - decimalIn))) /
                1e8;
        ...
        return (fairAmountOut * (10000 - slippageBips)) / 10000;
```
In the current implementation, the decimal of the exchange rate is set to `1e8`, which is insufficient for high-value tokens like WBTC.
```solidity
    function _getExchangeRate(
        IERC20 tokenIn,
        IERC20 tokenOut
    ) internal view returns (uint256 exchangeRate) {
        // Retrieve USD prices from oracles, scaled to 1e8
        uint256 priceIn = oracles[tokenIn].currentValue();
        uint256 priceOut = oracles[tokenOut].currentValue();

        // Return the exchange rate in 1e8 terms
@> 211  return (priceIn * 1e8) / priceOut;
    }
```

### Internal pre-conditions
WBTC should be allowed.

### External pre-conditions
N/A

### Attack Path
N/A

### Impact
Users lose more than 0.01% and more than $10 of their principal, even when they set the correct slippage.
This qualifies as Medium Severity.

### PoC
Let's consider the following scenario.

- Alice is going to buy WBTC using 20,000 USDC, set slippage bps as 100(1%).
- The current price of WBTC is 111,000 USD, the price of USDC is 1 USD.
- Then the exchange rate of USDC/WBTC is calculated as:
    ```solidity
    exchangeRate = priceIn * 1e8 / priceOut = 1e8 * 1e8 / (111,000 * 1e8) = 900.90 = 900
    ```
- The minimum amount that Alice should receive is calculated as:
    ```solidity
    fairAmountOut = (amountIn * exchangeRate * (10 ** (decimalOut - decimalIn))) / 1e8
                  = (20,000 * 1e6 * 900 * (10 ** (8 - 6))) / 1e8
                  = 18,000,000
    minAmountReceived = fairAmountOut * (10,000 - slippageBips) / 10,000
                      = 18,000,000 * (10,000 - 100) / 10,000
                      = 17,820,000
    ```
- The real amount that Alice should receive is calculated as:
    ```solidity
    realAmountOut = priceIn / priceOut * decimalOut
                  = 20,000 / 111,000 * 1e8
                  = 18,018,018
    minAmountReceived = realAmountOut * (10,000 - slippageBips) / 10,000
                      = 18,018,018 * (10,000 - 100) / 10,000
                      = 17,837,837
    ```
- Alice loses `17,837,837 - 17,820,000 = 17,837` WBTC, which has a value of `17,837 / 1e8 * 111,000 = 19.79`$
  The ratio of her loss is `17,837 / 17,837,837 * 100 = 0.0999`%.

As a result, users lose 0.01% and more than $10 of their principal. It qualifies as Medium severity.


### Mitigation
It is recommended to increase the precision of the exchange rate like `1e18`.

# Issue M-3: DOS during the filling of stopLimit orders causes users to incur losses 

Source: https://github.com/sherlock-audit/2025-07-oku-trade-order-types-judging/issues/225 

## Found by 
37H3RN17Y2, Phaethon, ZeroEx, bulgari, curly11, magbeans9, mohitisimmortal, mussucal, securewei

### Summary

There is a `maxPendingOrders=150` parameter to limit the number of orders in each contract. This restriction in  `Bracket.sol` and `stopLimit.sol` is independent, which could lead to DOS for existing orders in `stopLimit.sol`. When the `stopLimitPrice` is reached and if `Bracket.sol` has 150 orders, filling stoplimit orders to `Bracket.sol` will revert, which could incur losses to users.

### Root Cause

https://github.com/sherlock-audit/2025-07-oku-trade-order-types/blob/main/oku-custom-order-types/contracts/automatedTrigger/StopLimit.sol#L134-L190

In `stopLimit.sol`, when the exchange rate reaches the `stopLimitPrice` in an order, the `performUpkeep` function will be called to fill the order to `Bracket.sol` which will create a new order in `Bracket.sol`. 

https://github.com/sherlock-audit/2025-07-oku-trade-order-types/blob/main/oku-custom-order-types/contracts/automatedTrigger/Bracket.sol#L526-L548

Any order creation will call `_createOrder()` above and will check if the amount of pending orders is full. This means when `Bracket.sol` has 150 pending orders, any order in `stopLimit.sol` is not able to be executed, which could make users suffer a great loss.

### Internal Pre-conditions

`Bracket.sol` has 150 pending orders

### External Pre-conditions

exchange rate reaches stopLimitPrice of an order

### Attack Path

Let's give a simple example of how users could suffer loss due to this DOS problem
1.Suppose now WETH worth 3600 USDC
2.Alice successfully created an stop limit order of 10 WETH to USDC with stopLimitPrice=3500 and stopPrice=3300, takeProfit=4000
3.She set the stopSlippage to a large number(for example 500) which means she wants to sell all the WETH as fast as possible if the prices drops under 3300
4.Now WETH prices falls very quickly and `Bracket.sol` has 150 pending orders (this is very possibly happen because many users will create orders for USDC to WETH when price changes fast)
5.Now Alice's order is not able to be filled to `Bracket.sol` and be executed
6.WETH price drops to 3000 and a pending order in `Bracket.sol` is executed
7.Now Alice's order is filled in to `Bracket.sol` and executed but she suffers a great loss (she expected to get at least 31350 USDC but only get 30000 USDC now)

### Impact

This DOS will bring losses to existing orders in `stopLimit.sol` 

### PoC

_No response_

### Mitigation

 Do not record independently in `bracket.sol` and `stopLimit.sol` but record the pending order amount  in the master contract.

