pragma solidity 0.4.21;
pragma experimental "v0.5.0";

import { SafeMath } from "zeppelin-solidity/contracts/math/SafeMath.sol";
import { MarginCommon } from "./MarginCommon.sol";
import { MarginStorage } from "./MarginStorage.sol";
import { Vault } from "../Vault.sol";


/**
 * @title PositionGetters
 * @author dYdX
 *
 * A collection of public constant getter functions that allow users and applications to read the
 * state of any position stored in the dYdX protocol.
 */
contract PositionGetters is MarginStorage {
    using SafeMath for uint256;

    // ============ Public Constant Functions ============

    /**
     * Gets if a position is currently open
     *
     * @param  positionId  Unique ID of the position
     * @return             True if the position is exists and is open
     */
    function containsPosition(
        bytes32 positionId
    )
        view
        external
        returns (bool)
    {
        return MarginCommon.containsPositionImpl(state, positionId);
    }

    /**
     * Gets if a position is currently margin-called
     *
     * @param  positionId  Unique ID of the position
     * @return             True if the position is margin-called
     */
    function isPositionCalled(
        bytes32 positionId
    )
        view
        external
        returns (bool)
    {
        return (state.positions[positionId].callTimestamp > 0);
    }

    /**
     * Gets if a position was previously closed
     *
     * @param  positionId  Unique ID of the position
     * @return             True if the position is now closed
     */
    function isPositionClosed(
        bytes32 positionId
    )
        view
        external
        returns (bool)
    {
        return state.closedPositions[positionId];
    }

    /**
     * Gets the number of quote tokens currently locked up in Vault for a particular position
     *
     * @param  positionId  Unique ID of the position
     * @return             The number of quote tokens
     */
    function getPositionBalance(
        bytes32 positionId
    )
        view
        external
        returns (uint256)
    {
        if (!MarginCommon.containsPositionImpl(state, positionId)) {
            return 0;
        }

        return Vault(state.VAULT).balances(positionId, state.positions[positionId].quoteToken);
    }

    /**
     * Gets the time until the interest fee charged for the position will increase.
     * Returns 1 if the interest fee increases every second.
     * Returns 0 if the interest fee will never increase again.
     *
     * @param  positionId  Unique ID of the position
     * @return             The number of seconds until the interest fee will increase
     */
    function getTimeUntilInterestIncrease(
        bytes32 positionId
    )
        view
        external
        returns (uint256)
    {
        MarginCommon.Position storage positionObject = MarginCommon.getPositionObject(state, positionId);

        uint256 nextStep = MarginCommon.calculateEffectiveTimeElapsed(
            positionObject,
            block.timestamp
        );

        if (block.timestamp > nextStep) { // past maxDuration
            return 0;
        } else {
            // nextStep is the final second at which the calculated interest fee is the same as it
            // is currently, so add 1 to get the correct value
            return nextStep.add(1).sub(block.timestamp);
        }
    }

    /**
     * Gets the amount of base tokens currently needed to close the position completely, including
     * interest fees.
     *
     * @param  positionId  Unique ID of the position
     * @return             The number of base tokens
     */
    function getPositionOwedAmount(
        bytes32 positionId
    )
        view
        external
        returns (uint256)
    {
        MarginCommon.Position storage positionObject = MarginCommon.getPositionObject(state, positionId);

        return MarginCommon.calculateOwedAmount(
            positionObject,
            positionObject.principal.sub(positionObject.closedAmount),
            block.timestamp
        );
    }

    /**
     * Gets the amount of base tokens needed to close a given amount of the position at a given time,
     * including interest fees.
     *
     * @param  positionId   Unique ID of the position
     * @param  positionId   Amount of position being closed
     * @param  timestamp    Block timestamp in seconds of close
     * @return              The number of base tokens owed at the given time and amount
     */
    function getPositionOwedAmountAtTime(
        bytes32 positionId,
        uint256 amount,
        uint32  timestamp
    )
        view
        external
        returns (uint256)
    {
        MarginCommon.Position storage positionObject = MarginCommon.getPositionObject(state, positionId);

        return MarginCommon.calculateOwedAmount(
            positionObject,
            amount,
            timestamp
        );
    }

    /**
     * Gets the amount of base tokens that can be borrowed from a lender to add a given amount
     * onto the position at a given time.
     *
     * @param  positionId   Unique ID of the position
     * @param  positionId   Amount being added to position
     * @param  timestamp    Block timestamp in seconds of addition
     * @return              The number of base tokens that can be borrowed at the given
     *                      time and amount
     */
    function getLenderAmountForAddValueAtTime(
        bytes32 positionId,
        uint256 amount,
        uint32  timestamp
    )
        view
        external
        returns (uint256)
    {
        MarginCommon.Position storage positionObject = MarginCommon.getPositionObject(state, positionId);

        return MarginCommon.calculateLenderAmountForAddValue(
            positionObject,
            amount,
            timestamp
        );
    }

    // ============ All Properties ============

    /**
     * Get a Position by id. This does not validate the position exists. If the position does not
     * exist, all 0's will be returned.
     *
     * @param  positionId  Unique ID of the position
     * @return             Addresses corresponding to:
     *
     *                     [0] = baseToken
     *                     [1] = quoteToken
     *                     [2] = lender
     *                     [3] = owner
     *
     *                     Values corresponding to:
     *
     *                     [0] = principal
     *                     [1] = closedAmount
     *                     [2] = requiredDeposit
     *
     *                     Values corresponding to:
     *
     *                     [0] = callTimeLimit
     *                     [1] = startTimestamp
     *                     [2] = callTimestamp
     *                     [3] = maxDuration
     *                     [4] = interestRate
     *                     [5] = interestPeriod
     */
    function getPosition(
        bytes32 positionId
    )
        view
        external
        returns (
            address[4],
            uint256[3],
            uint32[6]
        )
    {
        MarginCommon.Position storage position = state.positions[positionId];

        return (
            [
                position.baseToken,
                position.quoteToken,
                position.lender,
                position.owner
            ],
            [
                position.principal,
                position.closedAmount,
                position.requiredDeposit
            ],
            [
                position.callTimeLimit,
                position.startTimestamp,
                position.callTimestamp,
                position.maxDuration,
                position.interestRate,
                position.interestPeriod
            ]
        );
    }

    // ============ Individual Properties ============

    function getPositionLender(
        bytes32 positionId
    )
        view
        external
        returns (address)
    {
        return state.positions[positionId].lender;
    }

    function getPositionOwner(
        bytes32 positionId
    )
        view
        external
        returns (address)
    {
        return state.positions[positionId].owner;
    }

    function getPositionQuoteToken(
        bytes32 positionId
    )
        view
        external
        returns (address)
    {
        return state.positions[positionId].quoteToken;
    }

    function getPositionBaseToken(
        bytes32 positionId
    )
        view
        external
        returns (address)
    {
        return state.positions[positionId].baseToken;
    }

    function getPositionAmount(
        bytes32 positionId
    )
        view
        external
        returns (uint256)
    {
        return state.positions[positionId].principal;
    }

    function getPositionClosedAmount(
        bytes32 positionId
    )
        view
        external
        returns (uint256)
    {
        return state.positions[positionId].closedAmount;
    }

    function getPositionUnclosedAmount(
        bytes32 positionId
    )
        view
        external
        returns (uint256)
    {
        return state.positions[positionId].principal.sub(state.positions[positionId].closedAmount);
    }

    function getPositionInterestRate(
        bytes32 positionId
    )
        view
        external
        returns (uint256)
    {
        return state.positions[positionId].interestRate;
    }

    function getPositionRequiredDeposit(
        bytes32 positionId
    )
        view
        external
        returns (uint256)
    {
        return state.positions[positionId].requiredDeposit;
    }

    function getPositionStartTimestamp(
        bytes32 positionId
    )
        view
        external
        returns (uint32)
    {
        return state.positions[positionId].startTimestamp;
    }

    function getPositionCallTimestamp(
        bytes32 positionId
    )
        view
        external
        returns (uint32)
    {
        return state.positions[positionId].callTimestamp;
    }

    function getPositionCallTimeLimit(
        bytes32 positionId
    )
        view
        external
        returns (uint32)
    {
        return state.positions[positionId].callTimeLimit;
    }

    function getPositionMaxDuration(
        bytes32 positionId
    )
        view
        external
        returns (uint32)
    {
        return state.positions[positionId].maxDuration;
    }

    function getPositioninterestPeriod(
        bytes32 positionId
    )
        view
        external
        returns (uint32)
    {
        return state.positions[positionId].interestPeriod;
    }
}