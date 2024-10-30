#![allow(dead_code)]

use anyhow::{format_err, Result};
use arrayref::array_refs;
use safe_transmute::{
    to_bytes::{transmute_one_to_bytes, transmute_to_bytes},
    transmute_many_pedantic, transmute_one_pedantic,
};
use serum_dex::state::{gen_vault_signer_key, AccountFlag, Market, MarketState, MarketStateV2};

use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::{
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
};

use std::{
    borrow::Cow,
    convert::{identity, TryFrom},
    mem::size_of,
};

#[derive(Debug, Default, Clone)]
pub struct MarketPubkeys {
    pub market: Box<Pubkey>,
    pub req_q: Box<Pubkey>,
    pub event_q: Box<Pubkey>,
    pub bids: Box<Pubkey>,
    pub asks: Box<Pubkey>,
    pub coin_vault: Box<Pubkey>,
    pub pc_vault: Box<Pubkey>,
    pub vault_signer_key: Box<Pubkey>,
    pub coin_mint: Box<Pubkey>,
    pub pc_mint: Box<Pubkey>,
    pub coin_lot_size: u64,
    pub pc_lot_size: u64,
}

#[cfg(target_endian = "little")]
fn remove_dex_account_padding<'a>(data: &'a [u8]) -> Result<Cow<'a, [u64]>> {
    use serum_dex::state::{ACCOUNT_HEAD_PADDING, ACCOUNT_TAIL_PADDING};
    let head = &data[..ACCOUNT_HEAD_PADDING.len()];
    if data.len() < ACCOUNT_HEAD_PADDING.len() + ACCOUNT_TAIL_PADDING.len() {
        return Err(format_err!(
            "dex account length {} is too small to contain valid padding",
            data.len()
        ));
    }
    if head != ACCOUNT_HEAD_PADDING {
        return Err(format_err!("dex account head padding mismatch"));
    }
    let tail = &data[data.len() - ACCOUNT_TAIL_PADDING.len()..];
    if tail != ACCOUNT_TAIL_PADDING {
        return Err(format_err!("dex account tail padding mismatch"));
    }
    let inner_data_range = ACCOUNT_HEAD_PADDING.len()..(data.len() - ACCOUNT_TAIL_PADDING.len());
    let inner: &'a [u8] = &data[inner_data_range];
    let words: Cow<'a, [u64]> = match transmute_many_pedantic::<u64>(inner) {
        Ok(word_slice) => Cow::Borrowed(word_slice),
        Err(transmute_error) => {
            let word_vec = transmute_error.copy().map_err(|e| e.without_src())?;
            Cow::Owned(word_vec)
        }
    };
    Ok(words)
}

#[cfg(target_endian = "little")]
pub async fn get_keys_for_market<'a>(
    client: &'a RpcClient,
    program_id: &'a Pubkey,
    market: &'a Pubkey,
) -> Result<MarketPubkeys> {
    let account_data: Vec<u8> = client.get_account_data(&market).await?;
    let words: Cow<[u64]> = remove_dex_account_padding(&account_data)?;
    let market_state: MarketState = {
        let account_flags = Market::account_flags(&account_data)?;
        if account_flags.intersects(AccountFlag::Permissioned) {
            println!("MarketStateV2");
            let state = transmute_one_pedantic::<MarketStateV2>(transmute_to_bytes(&words))
                .map_err(|e| e.without_src())?;
            state.check_flags(true)?;
            state.inner
        } else {
            println!("MarketStateV");
            let state = transmute_one_pedantic::<MarketState>(transmute_to_bytes(&words))
                .map_err(|e| e.without_src())?;
            state.check_flags(true)?;
            state
        }
    };
    let vault_signer_key =
        gen_vault_signer_key(market_state.vault_signer_nonce, market, program_id)?;
    assert_eq!(
        transmute_to_bytes(&identity(market_state.own_address)),
        market.as_ref()
    );
    Ok(MarketPubkeys {
        market: Box::new(*market),
        req_q: Box::new(
            Pubkey::try_from(transmute_one_to_bytes(&identity(market_state.req_q))).unwrap(),
        ),
        event_q: Box::new(
            Pubkey::try_from(transmute_one_to_bytes(&identity(market_state.event_q))).unwrap(),
        ),
        bids: Box::new(
            Pubkey::try_from(transmute_one_to_bytes(&identity(market_state.bids))).unwrap(),
        ),
        asks: Box::new(
            Pubkey::try_from(transmute_one_to_bytes(&identity(market_state.asks))).unwrap(),
        ),
        coin_vault: Box::new(
            Pubkey::try_from(transmute_one_to_bytes(&identity(market_state.coin_vault))).unwrap(),
        ),
        pc_vault: Box::new(
            Pubkey::try_from(transmute_one_to_bytes(&identity(market_state.pc_vault))).unwrap(),
        ),
        vault_signer_key: Box::new(vault_signer_key),
        coin_mint: Box::new(
            Pubkey::try_from(transmute_one_to_bytes(&identity(market_state.coin_mint))).unwrap(),
        ),
        pc_mint: Box::new(
            Pubkey::try_from(transmute_one_to_bytes(&identity(market_state.pc_mint))).unwrap(),
        ),
        coin_lot_size: market_state.coin_lot_size,
        pc_lot_size: market_state.pc_lot_size,
    })
}

#[cfg(target_endian = "little")]
pub async fn get_open_order<'a>(client: &'a RpcClient, open_order: &'a Pubkey) -> Result<()> {
    let open_order_data = &mut client.get_account_data(open_order).await?;
    let (_, data, _) =
        array_refs![&*open_order_data, 5, std::mem::size_of::<serum_dex::state::OpenOrders>();..;];
    let open_orders = unsafe {
        std::mem::transmute::<
            &[u8; std::mem::size_of::<serum_dex::state::OpenOrders>()],
            &serum_dex::state::OpenOrders,
        >(data)
    };
    println!(
        "native_coin_free:{}, native_coin_total:{}",
        identity(open_orders.native_coin_free),
        identity(open_orders.native_coin_total)
    );
    println!(
        "native_pc_free:{}, native_pc_total:{}",
        identity(open_orders.native_pc_free),
        identity(open_orders.native_pc_total)
    );
    println!("free_slot_bits:{:x}", identity(open_orders.free_slot_bits));
    println!("orders:{:?}", identity(open_orders.orders));
    Ok(())
}

fn hash_accounts(val: &[u64; 4]) -> u64 {
    val.iter().fold(0, |a, b| b.wrapping_add(a))
}

struct ListingKeys {
    market_key: Keypair,
    req_q_key: Keypair,
    event_q_key: Keypair,
    bids_key: Keypair,
    asks_key: Keypair,
    vault_signer_pk: Pubkey,
    vault_signer_nonce: u64,
}

async fn gen_listing_params(
    client: &RpcClient,
    program_id: &Pubkey,
    payer: &Pubkey,
) -> Result<(ListingKeys, Vec<Instruction>)> {
    // https://explorer.solana.com/tx/5ffFbv7m5nozcqVFsKC3o384Wesme4WNeChNUP4EPaEGnL7wQ1ZeUpvQUvp43BF5hc45pqnNpEiVHdWdzCTvQHQg
    let (market_key, create_market) =
        create_dex_account(client, program_id, payer, size_of::<MarketState>()).await?;
    let (req_q_key, create_req_q) = create_dex_account(client, program_id, payer, 5120).await?;
    let (event_q_key, create_event_q) =
        create_dex_account(client, program_id, payer, 1 << 18).await?;
    let (bids_key, create_bids) = create_dex_account(client, program_id, payer, 1 << 16).await?;
    let (asks_key, create_asks) = create_dex_account(client, program_id, payer, 1 << 16).await?;
    let (vault_signer_nonce, vault_signer_pk) = {
        let mut i = 0;
        loop {
            assert!(i < 100);
            if let Ok(pk) = gen_vault_signer_key(i, &market_key.pubkey(), program_id) {
                break (i, pk);
            }
            i += 1;
        }
    };
    let info = ListingKeys {
        market_key,
        req_q_key,
        event_q_key,
        bids_key,
        asks_key,
        vault_signer_pk,
        vault_signer_nonce,
    };
    let instructions = vec![
        create_market,
        create_req_q,
        create_event_q,
        create_bids,
        create_asks,
    ];
    Ok((info, instructions))
}

async fn gen_account_instr(
    client: &RpcClient,
    program_id: &Pubkey,
    payer: &Pubkey,
    key: &Pubkey,
    unpadded_len: usize,
) -> Result<Instruction> {
    let create_account_instr = solana_sdk::system_instruction::create_account(
        payer,
        key,
        client
            .get_minimum_balance_for_rent_exemption(unpadded_len)
            .await?,
        unpadded_len as u64,
        program_id,
    );
    Ok(create_account_instr)
}

async fn create_dex_account(
    client: &RpcClient,
    program_id: &Pubkey,
    payer: &Pubkey,
    unpadded_len: usize,
) -> Result<(Keypair, Instruction)> {
    let key = Keypair::new();
    let len = unpadded_len + 12;
    let instr = gen_account_instr(client, program_id, payer, &key.pubkey(), len).await?;
    Ok((key, instr))
}
