/*

    Copyright 2018 dYdX Trading Inc.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

*/

pragma solidity 0.4.24;
pragma experimental "v0.5.0";

import { ReentrancyGuard } from "zeppelin-solidity/contracts/ReentrancyGuard.sol";
import { Math } from "zeppelin-solidity/contracts/math/Math.sol";
import { SafeMath } from "zeppelin-solidity/contracts/math/SafeMath.sol";
import { Margin } from "../../Margin.sol";
import { MathHelpers } from "../../../lib/MathHelpers.sol";
import { TokenInteract } from "../../../lib/TokenInteract.sol";
import { MarginCommon } from "../../impl/MarginCommon.sol";
import { LoanOfferingVerifier } from "../../interfaces/LoanOfferingVerifier.sol";
import { OnlyMargin } from "../../interfaces/OnlyMargin.sol";
import { CancelMarginCallDelegator } from "../../interfaces/lender/CancelMarginCallDelegator.sol";
/* solium-disable-next-line max-len*/
import { ForceRecoverCollateralDelegator } from "../../interfaces/lender/ForceRecoverCollateralDelegator.sol";
import { IncreaseLoanDelegator } from "../../interfaces/lender/IncreaseLoanDelegator.sol";
import { LoanOwner } from "../../interfaces/lender/LoanOwner.sol";
import { MarginCallDelegator } from "../../interfaces/lender/MarginCallDelegator.sol";
import { MarginHelper } from "../lib/MarginHelper.sol";


/**
 * @title BucketLender
 * @author dYdX
 *
 * On-chain shared lender that allows anyone to deposit tokens into this contract to be used to
 * lend tokens for a particular position.
 */
contract BucketLender is
    OnlyMargin,
    LoanOwner,
    IncreaseLoanDelegator,
    MarginCallDelegator,
    CancelMarginCallDelegator,
    ForceRecoverCollateralDelegator,
    LoanOfferingVerifier,
    ReentrancyGuard
{
    using SafeMath for uint256;

    // ============ Events ============

    // TODO

    // ============ Structs ============

    struct LoanOffering {
        address owedToken;
        address heldToken;
        address payer;
        address signer;
        address owner;
        address taker;
        address positionOwner;
        address feeRecipient;
        address lenderFeeToken;
        address takerFeeToken;
        uint256 maximumAmount;
        uint256 minimumAmount;
        uint256 minimumHeldToken;
        uint256 lenderFee;
        uint256 takerFee;
        uint256 expirationTimestamp;
        uint256 salt;
        uint32  callTimeLimit;
        uint32  maxDuration;
        uint32  interestRate;
        uint32  interestPeriod;
    }

    struct PerBucket {
        mapping(uint256 => uint256) bucket;
        uint256 total;
    }

    struct PerAccount {
        mapping(address => uint256) account;
        uint256 total;
    }

    // ============ State Variables ============

    // Available token to lend
    PerBucket public available;

    // Current allocated principal for each bucket
    PerBucket public principal;

    // Bucket accounting for which accounts have deposited into that bucket
    mapping(uint256 => PerAccount) public weight;

    // Latest recorded value for totalOwedTokenRepaidToLender
    uint256 public cachedRepaidAmount = 0;

    // ============ Constants ============

    // Address of the token being lent
    address public OWED_TOKEN;

    // Address of the token held in the position as collateral
    address public HELD_TOKEN;

    // Time between new buckets
    uint32 public BUCKET_TIME;

    // Unique ID of the position
    bytes32 public POSITION_ID;

    mapping(address => bool) public TRUSTED_MARGIN_CALLERS;

    // ============ Constructor ============

    constructor(
        address margin,
        bytes32 positionId,
        address heldToken,
        address owedToken,
        uint32 bucketTime,
        address[] trustedMarginCallers
    )
        public
        OnlyMargin(margin)
    {
        POSITION_ID = positionId;
        HELD_TOKEN = heldToken;
        OWED_TOKEN = owedToken;
        BUCKET_TIME = bucketTime;

        for (uint256 i = 0; i < trustedMarginCallers.length; i++) {
            TRUSTED_MARGIN_CALLERS[trustedMarginCallers[i]] = true;
        }
    }

    // ============ Modifiers ============

    modifier onlyPosition(bytes32 positionId) {
        require(
            POSITION_ID == positionId
        );
        _;
    }

    // ============ Margin-Only State-Changing Functions ============

    /**
     * Function a smart contract must implement to be able to consent to a loan. The loan offering
     * will be generated off-chain and signed by a signer. The Margin contract will verify that
     * the signature for the loan offering was made by signer. The "loan owner" address will own the
     * loan-side of the resulting position.
     *
     * If true is returned, and no errors are thrown by the Margin contract, the loan will have
     * occurred. This means that verifyLoanOffering can also be used to update internal contract
     * state on a loan.
     *
     * @param  addresses    Array of addresses:
     *
     *  [0] = owedToken
     *  [1] = heldToken
     *  [2] = loan payer
     *  [3] = loan signer
     *  [4] = loan owner
     *  [5] = loan taker
     *  [6] = loan fee recipient
     *  [7] = loan lender fee token
     *  [8] = loan taker fee token
     *
     * @param  values256    Values corresponding to:
     *
     *  [0] = loan maximum amount
     *  [1] = loan minimum amount
     *  [2] = loan minimum heldToken
     *  [3] = loan lender fee
     *  [4] = loan taker fee
     *  [5] = loan expiration timestamp (in seconds)
     *  [6] = loan salt
     *
     * @param  values32     Values corresponding to:
     *
     *  [0] = loan call time limit (in seconds)
     *  [1] = loan maxDuration (in seconds)
     *  [2] = loan interest rate (annual nominal percentage times 10**6)
     *  [3] = loan interest update period (in seconds)
     *
     * @param  positionId   Unique ID of the position
     * @return              This address to accept, a different address to ask that contract
     */
    function verifyLoanOffering(
        address[10] addresses,
        uint256[7] values256,
        uint32[4] values32,
        bytes32 positionId
    )
        external
        onlyMargin
        nonReentrant
        returns (address)
    {
        LoanOffering memory loanOffering = parseLoanOffering(addresses, values256, values32);

        /* CHECK POSITIONID */
        require(positionId == POSITION_ID);

        /* CHECK ADDRESSES */
        require(loanOffering.owedToken == OWED_TOKEN);
        require(loanOffering.heldToken == HELD_TOKEN);
        require(loanOffering.payer == address(this));
        // no need to require anything about loanOffering.signer
        require(loanOffering.owner == address(this));
        // no need to require anything about loanOffering.taker
        // no need to require anything about loanOffering.positionOwner
        // no need to require anything about loanOffering.feeRecipient
        // no need to require anything about loanOffering.lenderFeeToken
        // no need to require anything about loanOffering.takerFeeToken

        /* CHECK VALUES256 */
        // no need to require anything about loanOffering.maximumAmount
        // no need to require anything about loanOffering.minimumAmount
        // no need to require anything about loanOffering.minimumHeldToken
        require(loanOffering.lenderFee == 0);
        // no need to require anything about loanOffering.takerFee
        // no need to require anything about loanOffering.expirationTimestamp
        // no need to require anything about loanOffering.salt

        /* CHECK VALUES32 */
        // no need to require anything about loanOffering.callTimeLimit
        // no need to require anything about loanOffering.maxDuration
        // no need to require anything about loanOffering.interestRate
        // no need to require anything about loanOffering.interestPeriod

        return address(this);
    }

    /**
     * Called by the Margin contract when anyone transfers ownership of a loan to this contract.
     * This function initializes this contract and returns this address to indicate to Margin
     * that it is willing to take ownership of the loan.
     *
     * @param  from        (unused)
     * @param  positionId  Unique ID of the position
     * @return             This address on success, throw otherwise
     */
    function receiveLoanOwnership(
        address from,
        bytes32 positionId
    )
        external
        onlyMargin
        onlyPosition(positionId)
        returns (address)
    {
        MarginCommon.Position memory position = MarginHelper.getPosition(DYDX_MARGIN, POSITION_ID);

        assert(position.principal > 0);
        assert(position.owedToken == OWED_TOKEN);
        assert(position.heldToken == HELD_TOKEN);

        // set relevant constants
        uint256 initialPrincipal = position.principal;
        principal.bucket[0] = initialPrincipal;
        principal.total = initialPrincipal;
        weight[0].total = weight[0].total.add(initialPrincipal);
        weight[0].account[from] = weight[0].account[from].add(initialPrincipal);

        return address(this);
    }

    /**
     * Called by Margin when additional value is added onto the position this contract
     * is lending for. Balance is added to the address that loaned the additional tokens.
     *
     * @param  payer           Address that loaned the additional tokens
     * @param  positionId      Unique ID of the position
     * @param  principalAdded  Amount that was added to the position
     *  param  lentAmount      (unused)
     * @return                 This address to accept, a different address to ask that contract
     */
    function increaseLoanOnBehalfOf(
        address payer,
        bytes32 positionId,
        uint256 principalAdded,
        uint256 lentAmount
    )
        external
        onlyMargin
        onlyPosition(positionId)
        returns (address)
    {
        assert(payer == address(this));

        // p2 is the principal after the add (p2 > p1)
        // p1 is the principal before the add
        uint256 p2 = Margin(DYDX_MARGIN).getPositionPrincipal(positionId);
        uint256 p1 = p2.sub(principalAdded);

        accountForClose(principal.total.sub(p1));

        accountForIncrease(principalAdded, lentAmount);

        assert(p2 == principal.total);

        return address(this);
    }

    /**
     * Function a contract must implement in order to let other addresses call marginCall().
     *
     * @param  caller         Address of the caller of the marginCall function
     * @param  positionId     Unique ID of the position
     * @param  depositAmount  Amount of heldToken deposit that will be required to cancel the call
     * @return                This address to accept, a different address to ask that contract
     */
    function marginCallOnBehalfOf(
        address caller,
        bytes32 positionId,
        uint256 depositAmount
    )
        external
        onlyMargin
        onlyPosition(positionId)
        returns (address)
    {
        require(TRUSTED_MARGIN_CALLERS[caller]);
        require(depositAmount == 0);

        return address(this);
    }

    /**
     * Function a contract must implement in order to let other addresses call cancelMarginCall().
     *
     * @param  canceler    Address of the caller of the cancelMarginCall function
     * @param  positionId  Unique ID of the position
     * @return             This address to accept, a different address to ask that contract
     */
    function cancelMarginCallOnBehalfOf(
        address canceler,
        bytes32 positionId
    )
        external
        onlyMargin
        onlyPosition(positionId)
        returns (address)
    {
        require(TRUSTED_MARGIN_CALLERS[canceler]);

        return address(this);
    }

    /**
     * Function a contract must implement in order to let other addresses call
     * forceRecoverCollateral().
     *
     *  param  recoverer   Address of the caller of the forceRecoverCollateral() function
     * @param  positionId  Unique ID of the position
     * @param  recipient   Address to send the recovered tokens to
     * @return             This address to accept, a different address to ask that contract
     */
    function forceRecoverCollateralOnBehalfOf(
        address /* recoverer */,
        bytes32 positionId,
        address recipient
    )
        external
        onlyMargin
        onlyPosition(positionId)
        returns (address)
    {
        require(recipient == address(this));

        return address(this);
    }

    // ============ Public State-Changing Functions ============

    /**
     * Allows users to deposit owedTokens into this contract. Allowance must be set on this contract
     * for "token" in at least the amount "amount".
     */
    function deposit(
        address token,
        address beneficiary,
        uint256 amount
    )
        external
        returns (uint256)
    {
        require(
            token == OWED_TOKEN
        );

        require(
            beneficiary != address(0)
        );

        TokenInteract.transferFrom(
            token,
            msg.sender,
            address(this),
            amount
        );

        uint256 bucket = getBucketNumber();

        weight[bucket].total = weight[bucket].total.add(amount);
        weight[bucket].account[beneficiary] = weight[bucket].account[beneficiary].add(amount);

        increase(available, bucket, amount);

        return bucket;
    }

    /**
     * Allow anyone to refresh the bucket amounts if part of the position was closed since the last
     * position increase. Favors earlier buckets.
     */
    function rebalanceBuckets(
    )
        external
    {
        uint256 marginPrincipal = Margin(DYDX_MARGIN).getPositionPrincipal(POSITION_ID);

        accountForClose(principal.total.sub(marginPrincipal));

        assert(marginPrincipal == principal.total);
    }

    // ============ Helper Functions ============

    function increase(
        PerBucket storage variable,
        uint256 bucket,
        uint256 amount
    )
        internal
    {
        require(amount > 0);
        variable.bucket[bucket] = variable.bucket[bucket].add(amount);
        variable.total = variable.total.add(amount);
    }

    function decrease(
        PerBucket storage variable,
        uint256 bucket,
        uint256 amount
    )
        internal
    {
        require(amount > 0);
        variable.bucket[bucket] = variable.bucket[bucket].sub(amount);
        variable.total = variable.total.sub(amount);
    }

    function getBucketNumber(
    )
        internal
        view
        returns (uint256)
    {
        uint256 marginTimestamp = Margin(DYDX_MARGIN).getPositionStartTimestamp(POSITION_ID);

        // position not created, allow deposits in the first bucket
        if (marginTimestamp == 0) {
            return 0;
        }

        return block.timestamp - marginTimestamp / BUCKET_TIME;
    }

    function accountForClose(
        uint256 principalRemoved
    )
        internal
    {
        if (principalRemoved == 0) {
            return;
        }

        uint256 newRepaidAmount = Margin(DYDX_MARGIN).getTotalOwedTokenRepaidToLender(POSITION_ID);

        // find highest bucket with outstanding principal
        uint256 i = 0;
        while (principal.bucket[i.add(1)] > 0) {
            i = i.add(1);
        }

        // (available up / principal down) starting at the highest bucket
        uint256 p_total = principalRemoved;
        uint256 a_total = newRepaidAmount.sub(cachedRepaidAmount);
        while (p_total > 0) {
            uint256 p_i = Math.min256(p_total, principal.bucket[i]);
            uint256 a_i = MathHelpers.getPartialAmount(a_total, p_total, p_i);

            increase(available, i, a_i);
            decrease(principal, i, p_i);

            p_total = p_total.sub(p_i);
            a_total = a_total.sub(a_i);

            i = i.sub(1);
        }

        cachedRepaidAmount = newRepaidAmount;
    }

    function accountForIncrease(
        uint256 principalAdded,
        uint256 lentAmount
    )
        internal
    {
        uint256 p_total = principalAdded;
        uint256 a_total = lentAmount;
        uint256 i = 0;
        while (p_total > 0 && (available.bucket[i] > 0 || principal.bucket[i] > 0)) {
            if (available.bucket[i] > 0) {
                uint256 a_i = Math.min256(a_total, available.bucket[i]);
                uint256 p_i = MathHelpers.getPartialAmount(p_total, a_total, a_i);

                decrease(available, i, a_i);
                increase(principal, i, p_i);

                p_total = p_total.sub(p_i);
                a_total = a_total.sub(a_i);
            }

            i = i.add(1);
        }
    }

    // ============ Parsing Functions ============

    function parseLoanOffering(
        address[10] addresses,
        uint256[7] values256,
        uint32[4] values32
    )
        private
        pure
        returns (LoanOffering memory)
    {
        LoanOffering memory loanOffering;

        fillLoanOfferingAddresses(loanOffering, addresses);
        fillLoanOfferingValues256(loanOffering, values256);
        fillLoanOfferingValues32(loanOffering, values32);

        return loanOffering;
    }

    function fillLoanOfferingAddresses(
        LoanOffering memory loanOffering,
        address[10] addresses
    )
        private
        pure
    {
        loanOffering.owedToken = addresses[0];
        loanOffering.heldToken = addresses[1];
        loanOffering.payer = addresses[2];
        loanOffering.signer = addresses[3];
        loanOffering.owner = addresses[4];
        loanOffering.taker = addresses[5];
        loanOffering.positionOwner = addresses[6];
        loanOffering.feeRecipient = addresses[7];
        loanOffering.lenderFeeToken = addresses[8];
        loanOffering.takerFeeToken = addresses[9];
    }

    function fillLoanOfferingValues256(
        LoanOffering memory loanOffering,
        uint256[7] values256
    )
        private
        pure
    {
        loanOffering.maximumAmount = values256[0];
        loanOffering.minimumAmount = values256[1];
        loanOffering.minimumHeldToken = values256[2];
        loanOffering.lenderFee = values256[3];
        loanOffering.takerFee = values256[4];
        loanOffering.expirationTimestamp = values256[5];
        loanOffering.salt = values256[6];
    }

    function fillLoanOfferingValues32(
        LoanOffering memory loanOffering,
        uint32[4] values32
    )
        private
        pure
    {
        loanOffering.callTimeLimit = values32[0];
        loanOffering.maxDuration = values32[1];
        loanOffering.interestRate = values32[2];
        loanOffering.interestPeriod = values32[3];
    }
}
