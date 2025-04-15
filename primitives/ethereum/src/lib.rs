// SPDX-License-Identifier: Apache-2.0
// This file is part of Frontier.
//
// Copyright (c) 2020-2022 Parity Technologies (UK) Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(unused_crate_dependencies)]

pub use ethereum::{
	AccessListItem, BlockV2 as Block, LegacyTransactionMessage, Log, ReceiptV3 as Receipt,
	TransactionAction, TransactionV2 as Transaction,
};
use ethereum::{Header, PartialHeader};
use ethereum_types::{Bloom, H160, H256, H64, U256};
use fp_evm::{CallOrCreateInfo, CheckEvmTransactionInput};
use frame_support::dispatch::{DispatchErrorWithPostInfo, PostDispatchInfo};
use scale_codec::{Decode, Encode};
use sp_std::{result::Result, vec::Vec};
use sha3::{Digest, Keccak256};

extern crate alloc;

type Bytes = alloc::vec::Vec<u8>;

pub trait ValidatedTransaction {
	fn apply(
		source: H160,
		transaction: Transaction,
	) -> Result<(PostDispatchInfo, CallOrCreateInfo), DispatchErrorWithPostInfo>;
}

#[derive(Clone, Debug, Eq, PartialEq, Encode, Decode)]
pub struct TransactionData {
	pub action: TransactionAction,
	pub input: Vec<u8>,
	pub nonce: U256,
	pub gas_limit: U256,
	pub gas_price: Option<U256>,
	pub max_fee_per_gas: Option<U256>,
	pub max_priority_fee_per_gas: Option<U256>,
	pub value: U256,
	pub chain_id: Option<u64>,
	pub access_list: Vec<(H160, Vec<H256>)>,
}

impl TransactionData {
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		action: TransactionAction,
		input: Vec<u8>,
		nonce: U256,
		gas_limit: U256,
		gas_price: Option<U256>,
		max_fee_per_gas: Option<U256>,
		max_priority_fee_per_gas: Option<U256>,
		value: U256,
		chain_id: Option<u64>,
		access_list: Vec<(H160, Vec<H256>)>,
	) -> Self {
		Self {
			action,
			input,
			nonce,
			gas_limit,
			gas_price,
			max_fee_per_gas,
			max_priority_fee_per_gas,
			value,
			chain_id,
			access_list,
		}
	}

	// The transact call wrapped in the extrinsic is part of the PoV, record this as a base cost for the size of the proof.
	pub fn proof_size_base_cost(&self) -> u64 {
		self.encode()
			.len()
			// signature
			.saturating_add(65)
			// pallet index
			.saturating_add(1)
			// call index
			.saturating_add(1) as u64
	}
}

impl From<TransactionData> for CheckEvmTransactionInput {
	fn from(t: TransactionData) -> Self {
		CheckEvmTransactionInput {
			to: if let TransactionAction::Call(to) = t.action {
				Some(to)
			} else {
				None
			},
			chain_id: t.chain_id,
			input: t.input,
			nonce: t.nonce,
			gas_limit: t.gas_limit,
			gas_price: t.gas_price,
			max_fee_per_gas: t.max_fee_per_gas,
			max_priority_fee_per_gas: t.max_priority_fee_per_gas,
			value: t.value,
			access_list: t.access_list,
		}
	}
}

impl From<&Transaction> for TransactionData {
	fn from(t: &Transaction) -> Self {
		match t {
			Transaction::Legacy(t) => TransactionData {
				action: t.action,
				input: t.input.clone(),
				nonce: t.nonce,
				gas_limit: t.gas_limit,
				gas_price: Some(t.gas_price),
				max_fee_per_gas: None,
				max_priority_fee_per_gas: None,
				value: t.value,
				chain_id: t.signature.chain_id(),
				access_list: Vec::new(),
			},
			Transaction::EIP2930(t) => TransactionData {
				action: t.action,
				input: t.input.clone(),
				nonce: t.nonce,
				gas_limit: t.gas_limit,
				gas_price: Some(t.gas_price),
				max_fee_per_gas: None,
				max_priority_fee_per_gas: None,
				value: t.value,
				chain_id: Some(t.chain_id),
				access_list: t
					.access_list
					.iter()
					.map(|d| (d.address, d.storage_keys.clone()))
					.collect(),
			},
			Transaction::EIP1559(t) => TransactionData {
				action: t.action,
				input: t.input.clone(),
				nonce: t.nonce,
				gas_limit: t.gas_limit,
				gas_price: None,
				max_fee_per_gas: Some(t.max_fee_per_gas),
				max_priority_fee_per_gas: Some(t.max_priority_fee_per_gas),
				value: t.value,
				chain_id: Some(t.chain_id),
				access_list: t
					.access_list
					.iter()
					.map(|d| (d.address, d.storage_keys.clone()))
					.collect(),
			},
		}
	}
}



#[derive(Clone, Debug, PartialEq, Eq)]
#[derive(rlp::RlpEncodable, rlp::RlpDecodable)]
#[cfg_attr(
feature = "with-codec",
derive(codec::Encode, codec::Decode, scale_info::TypeInfo)
)]
#[cfg_attr(feature = "with-serde", derive(serde::Serialize, serde::Deserialize))]
/// Ethereum header definition.
pub struct Header1559 {
	pub parent_hash: H256,
	pub ommers_hash: H256,
	pub beneficiary: H160,
	pub state_root: H256,
	pub transactions_root: H256,
	pub receipts_root: H256,
	pub logs_bloom: Bloom,
	pub difficulty: U256,
	pub number: U256,
	pub gas_limit: U256,
	pub gas_used: U256,
	pub timestamp: u64,
	pub extra_data: Bytes,
	pub mix_hash: H256,
	pub nonce: H64,
	pub base_fee_per_gas: U256,
}

impl Header1559 {
	#[allow(unused)]
	pub fn new(partial_header: PartialHeader, ommers_hash: H256, transactions_root: H256, base_fee_per_gas: U256) -> Self {
		Self {
			parent_hash: partial_header.parent_hash,
			ommers_hash,
			beneficiary: partial_header.beneficiary,
			state_root: partial_header.state_root,
			transactions_root,
			receipts_root: partial_header.receipts_root,
			logs_bloom: partial_header.logs_bloom,
			difficulty: partial_header.difficulty,
			number: partial_header.number,
			gas_limit: partial_header.gas_limit,
			gas_used: partial_header.gas_used,
			timestamp: partial_header.timestamp,
			extra_data: partial_header.extra_data,
			mix_hash: partial_header.mix_hash,
			nonce: partial_header.nonce,
			base_fee_per_gas,
		}
	}

	pub fn new_from_header(header: Header, base_fee_per_gas: U256) -> Self {
		Self {
			parent_hash: header.parent_hash,
			ommers_hash: header.ommers_hash,
			beneficiary: header.beneficiary,
			state_root: header.state_root,
			transactions_root: header.transactions_root,
			receipts_root: header.receipts_root,
			logs_bloom: header.logs_bloom,
			difficulty: header.difficulty,
			number: header.number,
			gas_limit: header.gas_limit,
			gas_used: header.gas_used,
			timestamp: header.timestamp,
			extra_data: header.extra_data,
			mix_hash: header.mix_hash,
			nonce: header.nonce,
			base_fee_per_gas,
		}
	}

	#[must_use]
	pub fn hash(&self) -> H256 {
		H256::from_slice(Keccak256::digest(&rlp::encode(self)).as_slice())
	}
}