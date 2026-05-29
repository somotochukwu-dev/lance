#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol, Vec, Bytes};

/* -----------------------------------------------------------------
   1. State Configurations & Schema Definitions
----------------------------------------------------------------- */

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobStatus {
    AwaitingFunding,
    Assigned,
    Completed,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DataKey {
    Admin,
    ClientVerified(Address), // Tracks identity verification constraints for clients
    JobConfig(u64),          // Maps Job ID to JobConfig parameters
    JobBids(u64),            // Maps Job ID to a Vector of submitted Bids
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobConfig {
    pub creator: Address,
    pub ipfs_cid: Bytes,       // Compressed project text parameters (IPFS Hash)
    pub budget: i128,
    pub status: JobStatus,
    pub freelancer: Option<Address>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bid {
    pub bidder: Address,
    pub amount: i128,
    pub timestamp: u64,
}

/* -----------------------------------------------------------------
   2. Explicit Event Schemas for Indexer & Verification Sync
----------------------------------------------------------------- */

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientVerificationEvent {
    pub client: Address,
    pub is_verified: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobCreatedIndexEvent {
    pub job_id: u64,
    pub creator: Address,
    pub ipfs_cid: Bytes,
    pub budget: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BidPlacedIndexEvent {
    pub job_id: u64,
    pub bidder: Address,
    pub amount: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobAssignedIndexEvent {
    pub job_id: u64,
    pub freelancer: Address,
    pub final_amount: i128,
}

/* -----------------------------------------------------------------
   3. Smart Contract Implementation
----------------------------------------------------------------- */

#[contract]
pub struct LanceJobRegistryContract;

#[contractimpl]
impl LanceJobRegistryContract {

    /// Initializes contract layout control patterns.
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("Registry already initialized");
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    /// Admin administrative capability to explicitly verify client identity status metrics.
    pub fn set_client_verification(env: Env, client: Address, status: bool) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).expect("Registry uninitialized");
        admin.require_auth();

        env.storage().persistent().set(&DataKey::ClientVerified(client.clone()), &status);

        env.events().publish(
            (Symbol::new(&env, "client_verified"), client.clone()),
            ClientVerificationEvent { client, is_verified: status },
        );
    }

    /// Post a new job posting entry after verifying strict client identity constraints.
    pub fn post_job(env: Env, job_id: u64, creator: Address, ipfs_cid: Bytes, budget: i128) {
        creator.require_auth();

        // Enforce Identity Validation Constraints
        let verification_key = DataKey::ClientVerified(creator.clone());
        let is_verified = env.storage().persistent().get(&verification_key).unwrap_or(false);
        if !is_verified {
            panic!("Identity constraint violation: Client profile must be fully verified to post jobs");
        }

        if budget <= 0 {
            panic!("Budget parameters must be positive value");
        }
        
        // Enforce basic IPFS hash length sanity boundary checking
        if ipfs_cid.len() < 32 {
            panic!("Invalid IPFS Content Identifier bounds provided");
        }

        let job_key = DataKey::JobConfig(job_id);
        if env.storage().persistent().has(&job_key) {
            panic!("Job ID identifier collision detected");
        }

        let config = JobConfig {
            creator: creator.clone(),
            ipfs_cid: ipfs_cid.clone(),
            budget,
            status: JobStatus::AwaitingFunding,
            freelancer: None,
        };

        env.storage().persistent().set(&job_key, &config);
        
        let bids_key = DataKey::JobBids(job_id);
        let empty_bids: Vec<Bid> = Vec::new(&env);
        env.storage().persistent().set(&bids_key, &empty_bids);

        env.events().publish(
            (Symbol::new(&env, "job_posted"), job_id),
            JobCreatedIndexEvent { job_id, creator, ipfs_cid, budget },
        );
    }

    /// Places a bid securely mapped to a specific job ID configuration entry.
    pub fn place_bid(env: Env, job_id: u64, bidder: Address, amount: i128) {
        bidder.require_auth();

        let job_key = DataKey::JobConfig(job_id);
        let job: JobConfig = env.storage().persistent().get(&job_key).expect("Target job registry context not found");

        if job.status != JobStatus::AwaitingFunding {
            panic!("Late submission error: Job no longer accepting active proposals");
        }
        if amount <= 0 {
            panic!("Bid valuation parameters must be a valid positive amount");
        }

        let bids_key = DataKey::JobBids(job_id);
        let mut bids: Vec<Bid> = env.storage().persistent().get(&bids_key).unwrap_or(Vec::new(&env));

        let new_bid = Bid {
            bidder: bidder.clone(),
            amount,
            timestamp: env.ledger().timestamp(),
        };
        bids.push_back(new_bid);
        env.storage().persistent().set(&bids_key, &bids);

        env.events().publish(
            (Symbol::new(&env, "bid_placed"), job_id),
            BidPlacedIndexEvent { job_id, bidder, amount },
        );
    }

    /// Accepts a proposal. Strictly enforces ownership boundaries.
    pub fn accept_bid(env: Env, job_id: u64, bid_index: u32) {
        let job_key = DataKey::JobConfig(job_id);
        let mut job: JobConfig = env.storage().persistent().get(&job_key).expect("Target job registry context not found");

        job.creator.require_auth();

        if job.status != JobStatus::AwaitingFunding {
            panic!("Invalid operational request sequence: Job state already locked or assigned");
        }

        let bids_key = DataKey::JobBids(job_id);
        let bids: Vec<Bid> = env.storage().persistent().get(&bids_key).expect("Bids collection store missing");

        if bid_index >= bids.len() {
            panic!("Out-of-bounds input error: Selected bid target index does not exist");
        }

        let chosen_bid = bids.get(bid_index).unwrap();

        job.status = JobStatus::Assigned;
        job.freelancer = Some(chosen_bid.bidder.clone());

        env.storage().persistent().set(&job_key, &job);

        env.events().publish(
            (Symbol::new(&env, "job_assigned"), job_id),
            JobAssignedIndexEvent {
                job_id,
                freelancer: chosen_bid.bidder,
                final_amount: chosen_bid.amount,
            },
        );
    }

    /* -----------------------------------------------------------------
       Public Getters
    ----------------------------------------------------------------- */

    pub fn get_job(env: Env, job_id: u64) -> Option<JobConfig> {
        env.storage().persistent().get(&DataKey::JobConfig(job_id))
    }

    pub fn get_bids(env: Env, job_id: u64) -> Vec<Bid> {
        env.storage().persistent().get(&DataKey::JobBids(job_id)).unwrap_or(Vec::new(&env))
    }

    pub fn is_client_verified(env: Env, client: Address) -> bool {
        env.storage().persistent().get(&DataKey::ClientVerified(client)).unwrap_or(false)
    }
}
