pragma solidity 0.4.21;
pragma experimental "v0.5.0";

import { AddressUtils } from "zeppelin-solidity/contracts/AddressUtils.sol";
import { LoanOwner } from "../interfaces/LoanOwner.sol";
import { PositionOwner } from "../interfaces/PositionOwner.sol";


/**
 * @title TransferInternal
 * @author dYdX
 *
 * This library contains the implementation for transferring ownership of loans and positions
 */
library TransferInternal {

    // ============ Events ============

    /**
     * Ownership of a loan was transferred to a new address
     */
    event LoanTransferred(
        bytes32 indexed positionId,
        address indexed from,
        address indexed to
    );

    /**
     * Ownership of a postions was transferred to a new address
     */
    event PositionTransferred(
        bytes32 indexed positionId,
        address indexed from,
        address indexed to
    );

    // ============ Internal Implementation Functions ============

    /**
     * Returns either the address of the new owner, or the address to which they wish to pass
     * ownership of the loan. This function does not actually set the state of the position
     *
     * @param  positionId  The Unique ID of the position
     * @param  oldOwner  The previous owner of the loan
     * @param  newOwner  The intended owner of the loan
     * @return           The address that the intended owner wishes to assign the loan to (may be
     *                   the same as the intended owner). Zero if ownership is rejected.
     */
    function grantLoanOwnership(
        bytes32 positionId,
        address oldOwner,
        address newOwner
    )
        internal
        returns (address)
    {
        // log event except upon position creation
        if (oldOwner != address(0)) {
            emit LoanTransferred(positionId, oldOwner, newOwner);
        }

        if (AddressUtils.isContract(newOwner)) {
            address nextOwner = LoanOwner(newOwner).receiveLoanOwnership(oldOwner, positionId);
            if (nextOwner != newOwner) {
                return grantLoanOwnership(positionId, newOwner, nextOwner);
            }
        }

        require (newOwner != address(0));
        return newOwner;
    }

    /**
     * Returns either the address of the new owner, or the address to which they wish to pass
     * ownership of the position. This function does not actually set the state of the position
     *
     * @param  positionId  The Unique ID of the position
     * @param  oldOwner  The previous owner of the position
     * @param  newOwner  The intended owner of the position
     * @return           The address that the intended owner wishes to assign the position to (may
     *                   be the same as the intended owner). Zero if ownership is rejected.
     */
    function grantPositionOwnership(
        bytes32 positionId,
        address oldOwner,
        address newOwner
    )
        internal
        returns (address)
    {
        // log event except upon position creation
        if (oldOwner != address(0)) {
            emit PositionTransferred(positionId, oldOwner, newOwner);
        }

        if (AddressUtils.isContract(newOwner)) {
            address nextOwner = PositionOwner(newOwner).receivePositionOwnership(oldOwner, positionId);
            if (nextOwner != newOwner) {
                return grantPositionOwnership(positionId, newOwner, nextOwner);
            }
        }

        require (newOwner != address(0));
        return newOwner;
    }
}