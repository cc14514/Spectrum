// Copyright 2015 The Spectrum Authors
// This file is part of the Spectrum library.
//
// The Spectrum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The Spectrum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the Spectrum library. If not, see <http://www.gnu.org/licenses/>.

package params

import "math/big"

const (
	MaximumExtraDataSize  uint64 = 32    // Maximum size extra data may be after Genesis.
	ExpByteGas            uint64 = 10    // Times ceil(log256(exponent)) for the EXP instruction.
	SloadGas              uint64 = 50    // Multiplied by the number of 32-byte words that are copied (round up) for any *COPY operation and added.
	CallValueTransferGas  uint64 = 9000  // Paid for CALL when the value transfer is non-zero.
	CallNewAccountGas     uint64 = 25000 // Paid for CALL when the destination address didn't exist prior.
	TxGas                 uint64 = 21000 // Per transaction not creating a contract. NOTE: Not payable on data of calls between transactions.
	TxGasContractCreation uint64 = 53000 // Per transaction that creates a contract. NOTE: Not payable on data of calls between transactions.
	TxDataZeroGas         uint64 = 4     // Per byte of data attached to a transaction that equals zero. NOTE: Not payable on data of calls between transactions.
	QuadCoeffDiv          uint64 = 512   // Divisor for the quadratic particle of the memory cost equation.
	SstoreSetGas          uint64 = 20000 // Once per SLOAD operation.
	LogDataGas            uint64 = 8     // Per byte in a LOG* operation's data.
	CallStipend           uint64 = 2300  // Free gas given at beginning of call.

	Sha3Gas          uint64 = 30    // Once per SHA3 operation.
	Sha3WordGas      uint64 = 6     // Once per word of the SHA3 operation's data.
	SstoreResetGas   uint64 = 5000  // Once per SSTORE operation if the zeroness changes from zero.
	SstoreClearGas   uint64 = 5000  // Once per SSTORE operation if the zeroness doesn't change.
	SstoreRefundGas  uint64 = 15000 // Once per SSTORE operation if the zeroness changes to zero.
	JumpdestGas      uint64 = 1     // Refunded gas, once per SSTORE operation if the zeroness changes to zero.
	EpochDuration    uint64 = 30000 // Duration between proof-of-work epochs.
	CallGas          uint64 = 40    // Once per CALL operation & message call transaction.
	CreateDataGas    uint64 = 200   //
	CallCreateDepth  uint64 = 1024  // Maximum depth of call/create stack.
	ExpGas           uint64 = 10    // Once per EXP instruction
	LogGas           uint64 = 375   // Per LOG* operation.
	CopyGas          uint64 = 3     //
	StackLimit       uint64 = 1024  // Maximum size of VM stack allowed.
	TierStepGas      uint64 = 0     // Once per operation, for a selection of them.
	LogTopicGas      uint64 = 375   // Multiplied by the * of the LOG*, per LOG transaction. e.g. LOG0 incurs 0 * c_txLogTopicGas, LOG4 incurs 4 * c_txLogTopicGas.
	CreateGas        uint64 = 32000 // Once per CREATE operation & contract-creation transaction.
	SuicideRefundGas uint64 = 24000 // Refunded following a suicide operation.
	MemoryGas        uint64 = 3     // Times the address of the (highest referenced byte in memory + 1). NOTE: referencing happens on read, write and in instructions such as RETURN and CALL.
	TxDataNonZeroGas uint64 = 68    // Per byte of data attached to a transaction that is not equal to zero. NOTE: Not payable on data of calls between transactions.

	BalanceGasFrontier      uint64 = 20 // The cost of a BALANCE operation
	ExtcodeSizeGasFrontier  uint64 = 20 // Cost of EXTCODESIZE before EIP 150 (Tangerine)
	ExtcodeCopyBaseFrontier uint64 = 20
	SloadGasFrontier        uint64 = 50
	CallGasFrontier         uint64 = 40  // Once per CALL operation & message call transaction.
	CallGasEIP150           uint64 = 700 // Static portion of gas for CALL-derivates after EIP 150 (Tangerine)

	BalanceGasEIP150      uint64 = 400 // The cost of a BALANCE operation after Tangerine
	ExtcodeSizeGasEIP150  uint64 = 700 // Cost of EXTCODESIZE after EIP 150 (Tangerine)
	SloadGasEIP150        uint64 = 200
	ExtcodeCopyBaseEIP150 uint64 = 700

	SstoreSentryGasEIP2200            uint64 = 2300  // Minimum gas required to be present for an SSTORE call, not consumed
	SstoreSetGasEIP2200               uint64 = 20000 // Once per SSTORE operation from clean zero to non-zero
	SstoreResetGasEIP2200             uint64 = 5000  // Once per SSTORE operation from clean non-zero to something else
	SstoreClearsScheduleRefundEIP2200 uint64 = 15000 // Once per SSTORE operation for clearing an originally existing storage slot

	NetSstoreClearRefund      uint64 = 15000 // Once per SSTORE operation for clearing an originally existing storage slot
	NetSstoreResetRefund      uint64 = 4800  // Once per SSTORE operation for resetting to the original non-zero value
	NetSstoreResetClearRefund uint64 = 19800 // Once per SSTORE operation for resetting to the original zero value

	NetSstoreNoopGas        uint64 = 200   // Once per SSTORE operation if the value doesn't change.
	NetSstoreInitGas        uint64 = 20000 // Once per SSTORE operation from clean zero.
	NetSstoreCleanGas       uint64 = 5000  // Once per SSTORE operation from clean non-zero.
	NetSstoreDirtyGas       uint64 = 200   // Once per SSTORE operation from dirty.
	SelfdestructRefundGas   uint64 = 24000 // Refunded following a selfdestruct operation.
	CreateBySelfdestructGas uint64 = 25000
	SelfdestructGasEIP150   uint64 = 5000 // Cost of SELFDESTRUCT post EIP 150 (Tangerine)
	// EXP has a dynamic portion depending on the size of the exponent
	ExpByteFrontier uint64 = 10 // was set to 10 in Frontier
	ExpByteEIP158   uint64 = 50 // was raised to 50 during Eip158 (Spurious Dragon)

	SloadGasEIP2200 uint64 = 800 // Cost of SLOAD after EIP 2200 (part of Istanbul)

	MaxCodeSize = 24576 // Maximum bytecode to permit for a contract

	// Precompiled contract gas prices

	EcrecoverGas            uint64 = 3000   // Elliptic curve sender recovery gas price
	Sha256BaseGas           uint64 = 60     // Base price for a SHA256 operation
	Sha256PerWordGas        uint64 = 12     // Per-word price for a SHA256 operation
	Ripemd160BaseGas        uint64 = 600    // Base price for a RIPEMD160 operation
	Ripemd160PerWordGas     uint64 = 120    // Per-word price for a RIPEMD160 operation
	IdentityBaseGas         uint64 = 15     // Base price for a data copy operation
	IdentityPerWordGas      uint64 = 3      // Per-work price for a data copy operation
	ModExpQuadCoeffDiv      uint64 = 20     // Divisor for the quadratic particle of the big int modular exponentiation
	Bn256AddGas             uint64 = 500    // Gas needed for an elliptic curve addition
	Bn256ScalarMulGas       uint64 = 40000  // Gas needed for an elliptic curve scalar multiplication
	Bn256PairingBaseGas     uint64 = 100000 // Base price for an elliptic curve pairing check
	Bn256PairingPerPointGas uint64 = 80000  // Per-point price for an elliptic curve pairing check

	ExtcodeHashGasConstantinople uint64 = 400   // Cost of EXTCODEHASH (introduced in Constantinople)
	Create2Gas                   uint64 = 32000 // Once per CREATE2 operation
)

var (
	GasLimitBoundDivisor   = big.NewInt(1024)                  // The bound divisor of the gas limit, used in update calculations.
	MinGasLimit            = big.NewInt(5000)                  // Minimum the gas limit may ever be.
	GenesisGasLimit        = big.NewInt(4712388)               // Gas limit of the Genesis block.
	TargetGasLimit         = new(big.Int).Set(GenesisGasLimit) // The artificial target
	DifficultyBoundDivisor = big.NewInt(2048)                  // The bound divisor of the difficulty, used in the update calculations.
	GenesisDifficulty      = big.NewInt(131072)                // Difficulty of the Genesis block.
	MinimumDifficulty      = big.NewInt(131072)                // The minimum that the difficulty may ever be.
	DurationLimit          = big.NewInt(13)                    // The decision boundary on the blocktime duration used to determine whether difficulty should go up or not.
	Sip004GasLimit         = big.NewInt(40000000)              // Minimum gas limit after hardfork
)

// add by liangc : alibp2p stream protocol IDs >>>>

type Alibp2pProtocol string

func (a Alibp2pProtocol) String() string { return string(a) }

const (
	MsgPidTxV1_0_0    Alibp2pProtocol = "/msg/1.0.0"
	MsgPidBlockV1_0_0 Alibp2pProtocol = "/msg/block/1.0.0"
	MsgPidBlockV2_0_0 Alibp2pProtocol = "/msg/block/2.0.0"
	MailBoxPidV1_0_0  Alibp2pProtocol = "/mailbox/1.0.0"
	UnknowProtocol    Alibp2pProtocol = ""
)

// let channel to support more protocols
var (
	// tx channel
	MsgpidTx = []Alibp2pProtocol{MsgPidTxV1_0_0}
	// blk channel
	MsgpidBlock = []Alibp2pProtocol{MsgPidBlockV1_0_0, MsgPidBlockV2_0_0}
	// relay channel
	Mailboxpid = []Alibp2pProtocol{MailBoxPidV1_0_0}

	ParseAlibp2pProtocol = func(p string) Alibp2pProtocol {
		return Alibp2pProtocol(p)
	}
)

var (
	MyId string //当前节点p256得的标致
	// TODO init >>>>
	Syncing    *int32
	MaxMsgSize uint64 //限制最大的msg大小 计算公式 gaslimit/40=msg最大尺寸 (40是0字节占用的gas大小)
	// TODO init <<<<
)

// add by liangc : alibp2p stream protocol IDs <<<<
