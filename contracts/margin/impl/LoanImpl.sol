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

import { Math } from "zeppelin-solidity/contracts/math/Math.sol";
import { SafeMath } from "zeppelin-solidity/contracts/math/SafeMath.sol";
import { MarginCommon } from "./MarginCommon.sol";
import { MarginState } from "./MarginState.sol";
import { TimestampHelper } from "../../lib/TimestampHelper.sol";
import { CancelMarginCallDelegator } from "../interfaces/lender/CancelMarginCallDelegator.sol";
import { MarginCallDelegator } from "../interfaces/lender/MarginCallDelegator.sol";


/**
 * @title LoanImpl
 * @author dYdX
 *
 * This library contains the implementation for the following functions of Margin:
 *
 *      - marginCall
 *      - cancelMarginCallImpl
 *      - cancelLoanOffering
 *      - approveLoanOffering
 */
library LoanImpl {
    using SafeMath for uint256;

    // ============ Events ============

    /**
     * A position was margin-called
     */
    event MarginCallInitiated(
        bytes32 indexed positionId,
        address indexed lender,
        address indexed owner,
        uint256 requiredDeposit
    );

    /**
     * A margin call was canceled
     */
    event MarginCallCanceled(
        bytes32 indexed positionId,
        address indexed lender,
        address indexed owner,
        uint256 depositAmount
    );

    /**
     * A loan offering was canceled before it was used. Any amount less than the
     * total for the loan offering can be canceled.
     */
    event LoanOfferingCanceled(
        bytes32 indexed loanHash,
        address indexed signer,
        address indexed feeRecipient,
        uint256 cancelAmount
    );

    /**
     * A loan offering was approved on-chain by a lender
     */
    event LoanOfferingApproved(
        bytes32 indexed loanHash,
        address indexed signer,
        address indexed feeRecipient
    );

    // ============ Public Implementation Functions ============

    function marginCallImpl(
        MarginState.State storage state,
        bytes32 positionId,
        uint256 requiredDeposit
    )
        public
    {
        MarginCommon.Position storage position =
            MarginCommon.getPositionFromStorage(state, positionId);

        require(
            position.callTimestamp == 0,
            "LoanImpl#marginCallImpl: The position has already been margin-called"
        );

        // Ensure lender consent
        marginCallOnBehalfOfRecurse(
            position.lender,
            msg.sender,
            positionId,
            requiredDeposit
        );

        position.callTimestamp = TimestampHelper.getBlockTimestamp32();
        position.requiredDeposit = requiredDeposit;

        emit MarginCallInitiated(
            positionId,
            position.lender,
            position.owner,
            requiredDeposit
        );
    }

    function cancelMarginCallImpl(
        MarginState.State storage state,
        bytes32 positionId
    )
        public
    {
        MarginCommon.Position storage position =
            MarginCommon.getPositionFromStorage(state, positionId);

        require(
            position.callTimestamp > 0,
            "LoanImpl#cancelMarginCallImpl: Position has not been margin-called"
        );

        // Ensure lender consent
        cancelMarginCallOnBehalfOfRecurse(
            position.lender,
            msg.sender,
            positionId
        );

        state.positions[positionId].callTimestamp = 0;
        state.positions[positionId].requiredDeposit = 0;

        emit MarginCallCanceled(
            positionId,
            position.lender,
            position.owner,
            0
        );
    }

    function cancelLoanOfferingImpl(
        MarginState.State storage state,
        address[10] addresses,
        uint256[7]  values256,
        uint32[4]   values32,
        uint256     cancelAmount
    )
        public
        returns (uint256)
    {
        MarginCommon.LoanOffering memory loanOffering = parseLoanOffering(
            addresses,
            values256,
            values32
        );

        require(
            msg.sender == loanOffering.payer || msg.sender == loanOffering.signer,
            "LoanImpl#cancelLoanOfferingImpl: Only loan offering payer or signer can cancel"
        );
        require(
            loanOffering.expirationTimestamp > block.timestamp,
            "LoanImpl#cancelLoanOfferingImpl: Loan offering has already expired"
        );

        uint256 remainingAmount = loanOffering.rates.maxAmount.sub(
            MarginCommon.getUnavailableLoanOfferingAmountImpl(state, loanOffering.loanHash)
        );
        uint256 amountToCancel = Math.min256(remainingAmount, cancelAmount);

        // If the loan was already fully canceled, then just return 0 amount was canceled
        if (amountToCancel == 0) {
            return 0;
        }

        state.loanCancels[loanOffering.loanHash] =
            state.loanCancels[loanOffering.loanHash].add(amountToCancel);

        emit LoanOfferingCanceled(
            loanOffering.loanHash,
            loanOffering.signer,
            loanOffering.feeRecipient,
            amountToCancel
        );

        return amountToCancel;
    }

    function approveLoanOfferingImpl(
        MarginState.State storage state,
        address[10] addresses,
        uint256[7]  values256,
        uint32[4]   values32
    )
        public
    {
        MarginCommon.LoanOffering memory loanOffering = parseLoanOffering(
            addresses,
            values256,
            values32
        );

        require(
            loanOffering.signer == msg.sender,
            "LoanImpl#approveLoanOfferingImpl: Only loan offering signer can approve"
        );
        require(
            loanOffering.expirationTimestamp > block.timestamp,
            "LoanImpl#approveLoanOfferingImpl: Loan offering is already expired"
        );

        if (state.approvedLoans[loanOffering.loanHash]) {
            return;
        }

        state.approvedLoans[loanOffering.loanHash] = true;

        emit LoanOfferingApproved(
            loanOffering.loanHash,
            loanOffering.signer,
            loanOffering.feeRecipient
        );
    }

    // ============ Private Helper-Functions ============

    function marginCallOnBehalfOfRecurse(
        address contractAddr,
        address who,
        bytes32 positionId,
        uint256 requiredDeposit
    )
        private
        returns (bool)
    {
        // no need to ask for permission
        if (who == contractAddr) {
            return;
        }

        address newContractAddr =
            MarginCallDelegator(contractAddr).marginCallOnBehalfOf(
                msg.sender,
                positionId,
                requiredDeposit
            );

        if (newContractAddr != contractAddr) {
            marginCallOnBehalfOfRecurse(
                newContractAddr,
                who,
                positionId,
                requiredDeposit
            );
        }
    }

    function cancelMarginCallOnBehalfOfRecurse(
        address contractAddr,
        address who,
        bytes32 positionId
    )
        private
        returns (bool)
    {
        // no need to ask for permission
        if (who == contractAddr) {
            return;
        }

        address newContractAddr =
            CancelMarginCallDelegator(contractAddr).cancelMarginCallOnBehalfOf(
                msg.sender,
                positionId
            );

        if (newContractAddr != contractAddr) {
            cancelMarginCallOnBehalfOfRecurse(
                newContractAddr,
                who,
                positionId
            );
        }
    }

    // ============ Parsing Functions ============

    function parseLoanOffering(
        address[10] addresses,
        uint256[7]  values256,
        uint32[4]   values32
    )
        private
        view
        returns (MarginCommon.LoanOffering memory)
    {
        MarginCommon.LoanOffering memory loanOffering = MarginCommon.LoanOffering({
            owedToken: addresses[0],
            heldToken: addresses[1],
            payer: addresses[2],
            signer: addresses[3],
            owner: addresses[4],
            taker: addresses[5],
            positionOwner: addresses[6],
            feeRecipient: addresses[7],
            lenderFeeToken: addresses[8],
            takerFeeToken: addresses[9],
            rates: parseLoanOfferRates(values256, values32),
            expirationTimestamp: values256[5],
            callTimeLimit: values32[0],
            maxDuration: values32[1],
            salt: values256[6],
            loanHash: 0,
            signature: MarginCommon.Signature({
                v: 0,
                r: "",
                s: ""
            })
        });

        loanOffering.loanHash = MarginCommon.getLoanOfferingHash(loanOffering);

        return loanOffering;
    }

    function parseLoanOfferRates(
        uint256[7] values256,
        uint32[4] values32
    )
        private
        pure
        returns (MarginCommon.LoanRates memory)
    {
        MarginCommon.LoanRates memory rates = MarginCommon.LoanRates({
            maxAmount: values256[0],
            minAmount: values256[1],
            minHeldToken: values256[2],
            interestRate: values32[2],
            lenderFee: values256[3],
            takerFee: values256[4],
            interestPeriod: values32[3]
        });

        return rates;
    }
}
