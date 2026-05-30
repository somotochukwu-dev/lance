#![no_std]

use soroban_sdk::{contract, contractimpl, contracttype, token, Address, Env, Vec};

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum EscrowStatus {
    Setup,
    Funded,
    WorkInProgress,
    Completed,
    Disputed,
    Resolved,
    Refunded,
}

impl EscrowStatus {
    /// Requirement [SC-ESC-013]: Validate state machine transitions across multi-milestone gigs.
    ///
    /// Every state-mutating function in `EscrowContract` calls this guard before updating
    /// persistent storage, ensuring the escrow lifecycle is a strict directed acyclic graph:
    ///
    /// ```text
    ///   Setup ──► Funded ──► WorkInProgress ──► Completed
    ///     │          │              │
    ///     │          └──────────────┼──► Disputed ──► Resolved
    ///     │                        │                    │
    ///     └────────────────────────┴────────────────────┴──► Refunded
    /// ```
    ///
    /// Returning `Err(InvalidStateTransition)` causes the calling function to surface
    /// error code `#11` to the caller — equivalent to a 422 Unprocessable Entity at
    /// the protocol layer.  This is distinct from `Unauthorized` (`#3`) which covers
    /// authentication failures.
    ///
    /// The `WorkInProgress → WorkInProgress` self-transition is intentional: each
    /// partial milestone release keeps the job in `WorkInProgress` until all funds
    /// are released, at which point it transitions to `Completed`.
    pub fn validate_transition(&self, next: &EscrowStatus) -> Result<(), EscrowError> {
        match (self, next) {
            // [SC-ESC-013]: Setup is the initial configuration phase; only Funded (deposit
            // received) or Refunded (brief cancelled before funding) are valid exits.
            (EscrowStatus::Setup, EscrowStatus::Funded) => Ok(()),
            (EscrowStatus::Setup, EscrowStatus::Refunded) => Ok(()),
            // [SC-ESC-013]: Funded allows work to start, dispute, partial refund, or
            // immediate completion if a single-milestone job is released all at once.
            (EscrowStatus::Funded, EscrowStatus::WorkInProgress) => Ok(()),
            (EscrowStatus::Funded, EscrowStatus::Completed) => Ok(()),
            (EscrowStatus::Funded, EscrowStatus::Disputed) => Ok(()),
            (EscrowStatus::Funded, EscrowStatus::Refunded) => Ok(()),
            // [SC-ESC-013]: WorkInProgress self-loop covers partial milestone releases.
            // Transitions to Completed (all milestones released), Disputed (conflict raised),
            // or Refunded (client cancels mid-gig) are valid exits.
            (EscrowStatus::WorkInProgress, EscrowStatus::WorkInProgress) => Ok(()),
            (EscrowStatus::WorkInProgress, EscrowStatus::Completed) => Ok(()),
            (EscrowStatus::WorkInProgress, EscrowStatus::Disputed) => Ok(()),
            (EscrowStatus::WorkInProgress, EscrowStatus::Refunded) => Ok(()),
            // [SC-ESC-013]: A Disputed job can only be Resolved (judge adjudicates) or
            // Refunded (dispute deadline expires via `expire_dispute`).  No other exits.
            (EscrowStatus::Disputed, EscrowStatus::Resolved) => Ok(()),
            (EscrowStatus::Disputed, EscrowStatus::Refunded) => Ok(()),
            // [SC-ESC-013]: All other transitions are invalid.  Completed, Resolved, and
            // Refunded are terminal — they have no valid outgoing edges.
            _ => Err(EscrowError::InvalidStateTransition),
        }
    }
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum MilestoneStatus {
    Pending,
    Released,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Milestone {
    pub amount: i128,
    pub status: MilestoneStatus,
}

#[contracttype]
#[derive(Clone)]
pub struct EscrowJob {
    pub client: Address,
    pub freelancer: Address,
    pub token: Address,
    pub total_amount: i128,
    pub released_amount: i128,
    pub status: EscrowStatus,
    pub created_at: u64,
    pub expires_at: u64,
    pub milestones: Vec<Milestone>,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct TreasuryConfig {
    pub routing_address: Address,
    pub fee_bps: u32,
}

#[contracttype]
#[derive(Clone)]
pub struct FeeConfigUpdatedEvent {
    pub treasury: Address,
    pub fee_bps: u32,
    pub updated_at: u64,
}

pub const MAX_FEE_BPS: u32 = 10_000;

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ContractConfig {
    pub admin: Address,
    pub agent_judge: Address,
}

#[contracttype]
#[derive(Clone)]
pub struct UpgradeAdminSetEvent {
    pub old_admin: Option<Address>,
    pub new_admin: Address,
    pub updated_at: u64,
}

#[contracterror]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EscrowError {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    Unauthorized = 3,
    InvalidInput = 4,
    JobNotFound = 5,
    InvalidState = 6,
    AmountMismatch = 7,
    NoPendingMilestones = 8,
    JobRegistrySyncFailed = 9,
    UpgradeUnauthorized = 10,
    InvalidStateTransition = 11,
    ReentrancyDetected = 12,
    MultisigRequired = 13,
    FeeTooHigh = 21,
    NothingToSweep = 22,
    InsufficientSignatures = 14,
    AlreadySigned = 15,
    ArithmeticError = 16,
    UpgradeAdminAlreadySet = 17,
    UpgradeAdminNotSet = 18,
    ArithmeticOverflow = 19,
    DisputeResolutionExpired = 20,
    MaxMilestonesExceeded = 21,
    FeeTooHigh = 22,
    NothingToSweep = 23,
    FeeTooHigh = 21,
    NothingToSweep = 22,
    ReentrantCall = 11,
}

/// Maximum platform fee, in basis points (100% = 10_000 bps).
pub const MAX_FEE_BPS: u32 = 10_000;

/// Requirement [SC-ESC-016]: Maximum number of milestones allowed per escrow job.
///
/// This hard cap serves two purposes:
/// 1. **Storage efficiency** — each `Milestone` struct is written to Soroban persistent
///    storage as part of the `EscrowJob` value.  Unbounded growth would bloat the
///    ledger entry beyond the Soroban footprint limits and drive up rent fees.
/// 2. **WASM execution safety** — iteration over milestones during `deposit`,
///    `release_milestone`, and `amend_milestones` is O(n); capping at 12 guarantees
///    these loops stay well inside the Soroban instruction-count block boundary.
///
/// Checked arithmetic (`checked_add`, `checked_mul`) is used throughout all
/// milestone-amount summation paths to prevent silent integer overflow.
pub const MAX_MILESTONES: u32 = 12;

pub enum DataKey {
    Job(u64),
    Config,
    GuardFlag(u64),
    Treasury,
}

#[contracttype]
#[derive(Clone)]
pub struct DisputeRaisedEvent {
    pub job_id: u64,
    pub initiator: Address,
    pub milestones_released: u32,
    pub milestones_total: u32,
    pub raised_at: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct DepositEvent {
    pub job_id: u64,
    pub amount: i128,
    pub deposited_at: u64,
}
#[contracttype]
#[derive(Clone)]
pub struct ReleaseMilestoneEvent {
    pub job_id: u64,
    pub milestone_index: u32,
    pub amount: i128,
    pub released_at: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct OpenDisputeEvent {
    pub job_id: u64,
    pub initiator: Address,
    pub opened_at: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct JobRegistryConfiguredEvent {
    pub configured_by: Address,
    pub registry_contract: Address,
    pub configured_at: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct RegistryDisputeSyncedEvent {
    pub job_id: u64,
    pub registry_contract: Address,
    pub synced_at: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct ContractUpgradedEvent {
    pub by_admin: Address,
    pub new_wasm_hash: BytesN<32>,
    pub upgraded_at: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct BriefCanceledEvent {
    pub job_id: u64,
    pub refunded_amount: i128,
    pub canceled_by: Address,
    pub canceled_at: u64,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct MultisigConfig {
    pub signers: Vec<Address>,
    pub required_signatures: u32,
    pub current_signatures: Vec<Address>,
}

#[contracttype]
#[derive(Clone)]
pub struct MultisigConfiguredEvent {
    pub job_id: u64,
    pub required_signatures: u32,
    pub total_signers: u32,
    pub configured_at: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct MultisigSignedEvent {
    pub job_id: u64,
    pub signer: Address,
    pub signature_count: u32,
    pub signed_at: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct DisputeExpiredEvent {
    pub job_id: u64,
    pub refunded_to: Address,
    pub amount: i128,
    pub expired_at: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct FeeConfigUpdatedEvent {
    pub treasury: Option<Address>,
    pub fee_bps: u32,
    pub updated_at: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct LockupUpdatedEvent {
    pub job_id: u64,
    pub expires_at: u64,
    pub updated_at: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct EmergencySweepEvent {
    pub job_id: u64,
    pub admin: Address,
    pub rescue_address: Address,
    pub amount: i128,
    pub swept_at: u64,
}

#[contracttype]
#[derive(Clone)]
pub struct MilestonesAmendedEvent {
    pub job_id: u64,
    pub milestone_count: u32,
    pub remaining_amount: i128,
    pub amended_at: u64,
}

fn enter_reentrancy_guard(env: &Env) {
struct ReentrancyGuard<'a> {
    env: &'a Env,
}

impl Drop for ReentrancyGuard<'_> {
    fn drop(&mut self) {
        self.env.storage().instance().remove(&DataKey::Locked);
    }
}

fn enter_reentrancy_guard(env: &Env) -> ReentrancyGuard<'_> {
    if env.storage().instance().has(&DataKey::Locked) {
        panic_with_error!(env, EscrowError::ReentrancyDetected);
    }
    env.storage().instance().set(&DataKey::Locked, &());
    ReentrancyGuard { env }
}

fn checked_i128_add(lhs: i128, rhs: i128) -> Result<i128, EscrowError> {
    lhs.checked_add(rhs).ok_or(EscrowError::InvalidInput)
}

#[contract]
pub struct EscrowContract;

#[contractimpl]
impl EscrowContract {
    pub fn initialize(env: Env, admin: Address, agent_judge: Address) {
        if env.storage().instance().has(&DataKey::Config) {
            panic!("already initialized");
        }
        let config = ContractConfig { admin, agent_judge };
        env.storage().instance().set(&DataKey::Config, &config);
    }

    /// Admin can update the Agent Judge address.
    pub fn set_agent_judge(env: Env, new_agent_judge: Address) {
        let mut config: ContractConfig = env
            .storage()
            .instance()
            .get(&DataKey::Config)
            .expect("not initialized");
        config.admin.require_auth();
        config.agent_judge = new_agent_judge;
        env.storage()
            .instance()
            .set(&DataKey::Config, &config);
    }

    pub fn configure_treasury(env: Env, routing_address: Address, fee_bps: u32) {
        let config: ContractConfig = env
            .storage()
            .instance()
            .get(&DataKey::Config)
            .expect("not initialized");
        config.admin.require_auth();

        assert!(fee_bps <= MAX_FEE_BPS, "FeeTooHigh");

        let config = TreasuryConfig {
            routing_address: routing_address.clone(),
            fee_bps,
        };

        env.storage().instance().set(&DataKey::Treasury, &config);

        env.events().publish(
            ("escrow", "FeeConfigUpdated"),
            FeeConfigUpdatedEvent {
                treasury: routing_address,
                fee_bps,
                updated_at: env.ledger().timestamp(),
            },
        );
    }

    pub fn get_treasury(env: Env) -> Option<Address> {
        if let Some(config) = env.storage().instance().get::<_, TreasuryConfig>(&DataKey::Treasury) {
            Some(config.routing_address)
        } else {
            None
        }
    }

    /// Client creates a job entry in Setup phase.
    pub fn create_job(
        env: Env,
        job_id: u64,
        client: Address,
        freelancer: Address,
        token_addr: Address,
    ) {
        client.require_auth();
        let key = DataKey::Job(job_id);
        if env.storage().persistent().has(&key) {
            panic!("job already exists");
        }
        let now: u64 = env.ledger().timestamp();
        let expires_at = now
            .checked_add(
                30u64
                    .checked_mul(24)
                    .expect("overflow")
                    .checked_mul(60)
                    .expect("overflow")
                    .checked_mul(60)
                    .expect("overflow"),
            )
            .expect("overflow");

        let job = EscrowJob {
            client,
            freelancer,
            token: token_addr,
            total_amount: 0,
            released_amount: 0,
            status: EscrowStatus::Setup,
            created_at: now,
            expires_at,
            milestones: Vec::new(&env),
        };
        env.storage().persistent().set(&key, &job);
    }

    /// Requirement [SC-ESC-016]: Add a milestone to the job during the Setup phase.
    ///
    /// Milestones partition the total escrow budget into discrete delivery tranches that
    /// the client unlocks incrementally via `release_milestone` or `release_funds`.
    ///
    /// **Authorization**: only the job's client may add milestones (`env.require_auth`).
    ///
    /// **State guard**: only valid in `Setup` state.  Once `deposit` transitions the job
    /// to `Funded`, the milestone structure is locked (modifications require `amend_milestones`
    /// with dual-party authorization).
    ///
    /// **Partition count limit** ([SC-ESC-016]): adding a 13th milestone (or beyond) is
    /// rejected with `MaxMilestonesExceeded` (error code `#21`).  This cap prevents
    /// unbounded persistent-storage growth and keeps WASM instruction counts bounded.
    ///
    /// **Checked arithmetic**: all milestone amount accumulation in `deposit` uses
    /// `checked_add` to guard against `i128` overflow when summing across all partitions.
    ///
    /// # Errors
    /// - `JobNotFound` — no persistent record for `job_id`.
    /// - `Unauthorized` — caller is not the job client.
    /// - `InvalidState` — job is not in `Setup` state.
    /// - `InvalidInput` — `amount` is zero or negative.
    /// - `MaxMilestonesExceeded` — already at the `MAX_MILESTONES` (12) limit.
    pub fn add_milestone(env: Env, job_id: u64, amount: i128) -> Result<(), EscrowError> {
        let key = DataKey::Job(job_id);
        let mut job: EscrowJob = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(EscrowError::JobNotFound)?;
        Self::bump_job_ttl(&env, &key);
        // [SC-ESC-016]: Only the authenticated client may mutate the milestone set.
        job.client.require_auth();
        // [SC-ESC-016]: Milestones are only configurable during Setup; once funded the
        // partition set is immutable without explicit `amend_milestones` dual-auth.
        if job.status != EscrowStatus::Setup {
            return Err(EscrowError::InvalidState);
        }
        // [SC-ESC-016]: Reject zero or negative amounts to prevent zero-value milestones
        // that would misalign the deposit total vs. milestone sum check.
        if amount <= 0 || amount > Self::MAX_MILESTONE_AMOUNT {
            return Err(EscrowError::InvalidInput);
        }
        
        let next_total = checked_i128_add(job.total_amount, amount)?;
        if next_total > Self::MAX_JOB_BUDGET {
            return Err(EscrowError::InvalidInput);
        }

        // [SC-ESC-016]: Enforce maximum milestone partition count.
        // This is the primary invariant of this task — cap at MAX_MILESTONES (12) to
        // bound ledger footprint and keep on-chain iteration within safe gas limits.
        if job.milestones.len() >= MAX_MILESTONES {
            return Err(EscrowError::MaxMilestonesExceeded);
        }
    /// Add a milestone to the job (setup phase only).
    pub fn add_milestone(env: Env, job_id: u64, amount: i128) {
        let key = DataKey::Job(job_id);
        let mut job: EscrowJob = env.storage().persistent().get(&key).expect("job not found");
        job.client.require_auth();
        assert!(job.status == EscrowStatus::Setup, "not in setup phase");
        assert!(amount > 0, "amount must be > 0");

        let milestone = Milestone {
            amount,
            status: MilestoneStatus::Pending,
        };
        job.milestones.push_back(milestone);
        env.storage().persistent().set(&key, &job);
    }

    /// Client deposits total amount and transitions job to Funded.
    pub fn deposit(env: Env, job_id: u64, amount: i128) {
        let key = DataKey::Job(job_id);
        let mut job: EscrowJob = env.storage().persistent().get(&key).expect("job not found");
        job.client.require_auth();
        assert!(
            job.status == EscrowStatus::Setup,
            "already funded or invalid state"
        );
        assert!(amount > 0, "amount must be > 0");
        assert!(job.milestones.len() > 0, "no milestones defined");

        let mut total_milestones_amount = 0i128;
        for m in job.milestones.iter() {
            total_milestones_amount = total_milestones_amount
                .checked_add(m.amount)
                .expect("overflow");
        }
        assert!(
            total_milestones_amount == amount,
            "sum of milestones must equal total amount"
        );

        let token_client = token::Client::new(&env, &job.token);
        token_client.transfer(&job.client, &env.current_contract_address(), &amount);

        job.total_amount = amount;
        job.status = EscrowStatus::Funded;
        env.storage().persistent().set(&key, &job);
    }

    /// Client approves a milestone -- releases next pending milestone to freelancer.
    pub fn release_milestone(env: Env, job_id: u64, caller: Address) {
        caller.require_auth();
        Self::check_reentrancy(&env, job_id);

        let key = DataKey::Job(job_id);
        let mut job: EscrowJob = env.storage().persistent().get(&key).expect("job not found");

        assert!(
            job.status == EscrowStatus::Funded || job.status == EscrowStatus::WorkInProgress,
            "invalid state"
        );
        assert!(caller == job.client, "only client can release");

        let mut found_idx = None;
        for i in 0..job.milestones.len() {
            let m = job.milestones.get(i).unwrap();
            if m.status == MilestoneStatus::Pending {
                found_idx = Some(i);
                break;
            }
        }

        let idx = found_idx.expect("no pending");
        Self::set_guard(&env, job_id);
        Self::release_milestone_internal(&env, job_id, &mut job, idx);
        Self::clear_guard(&env, job_id);
    }

    fn payout_with_fee(env: &Env, _job_id: u64, job: &EscrowJob, amount: i128) {
        let token_client = token::Client::new(env, &job.token);
        let fee_bps = Self::get_fee_bps(env.clone());
        let mut payout_amount = amount;

        if fee_bps > 0 {
            if let Some(treasury) = Self::get_treasury(env.clone()) {
                let fee_amount = amount
                    .checked_mul(fee_bps as i128)
                    .unwrap_or(0)
                    .checked_div(MAX_FEE_BPS as i128)
                    .unwrap_or(0);
                
                payout_amount = amount.checked_sub(fee_amount).unwrap_or(amount);

                if fee_amount > 0 {
                    token_client.transfer(&env.current_contract_address(), &treasury, &fee_amount);
                }
            }
        }

        if payout_amount > 0 {
            token_client.transfer(&env.current_contract_address(), &job.freelancer, &payout_amount);
        }
    }

    /// Happy-path release for an explicit milestone index (0-based).
    pub fn release_funds(env: Env, job_id: u64, caller: Address, milestone_index: u32) {
        caller.require_auth();
        Self::check_reentrancy(&env, job_id);

        let key = DataKey::Job(job_id);
        let mut job: EscrowJob = env.storage().persistent().get(&key).expect("job not found");

        assert!(
            job.status == EscrowStatus::Funded || job.status == EscrowStatus::WorkInProgress,
            "invalid state"
        );
        assert!(caller == job.client, "unauthorized");
        assert!(milestone_index < job.milestones.len(), "invalid");

        let milestone = job.milestones.get(milestone_index).expect("invalid");
        assert!(milestone.status == MilestoneStatus::Pending, "released");

        Self::set_guard(&env, job_id);
        Self::release_milestone_internal(&env, job_id, &mut job, milestone_index);
        Self::clear_guard(&env, job_id);
    }

    /// Either party opens a dispute, locking remaining funds.
    pub fn open_dispute(env: Env, job_id: u64, caller: Address) {
        caller.require_auth();

        let key = DataKey::Job(job_id);
        let mut job: EscrowJob = env.storage().persistent().get(&key).expect("job not found");

        if !(caller == job.client || caller == job.freelancer) {
            return Err(EscrowError::Unauthorized);
        }

        let next_status = EscrowStatus::Disputed;
        job.status.validate_transition(&next_status)?;
        job.status = next_status;
        job.dispute_deadline = env.ledger().timestamp()
            .checked_add(Self::DISPUTE_RESOLUTION_WINDOW)
            .ok_or(EscrowError::ArithmeticError)?;
        log!(&env, "open_dispute: job {}", job_id);
        env.storage().persistent().set(&key, &job);
        Self::bump_job_ttl(&env, &key);

        Self::sync_dispute_to_job_registry(&env, job_id)?;

        env.events().publish(
            ("escrow", "OpenDispute"),
            (job_id, caller, env.ledger().timestamp()),
        assert!(
            job.status == EscrowStatus::Funded || job.status == EscrowStatus::WorkInProgress,
            "job not in active/funded state"
        );
        assert!(
            caller == job.client || caller == job.freelancer,
            "unauthorized"
        );

        job.status = EscrowStatus::Disputed;
        env.storage().persistent().set(&key, &job);
    }

    /// Either party formally raises a dispute with on-chain event emission.
    /// Locks funds, transitions state to Disputed, and signals the AI Judge.
    pub fn raise_dispute(env: Env, job_id: u64, caller: Address) {
        // 1. Authenticate the caller
        caller.require_auth();

        let key = DataKey::Job(job_id);
        let mut job: EscrowJob = env.storage().persistent().get(&key).expect("job not found");

        // 2. Only client or freelancer may raise a dispute
        assert!(
            caller == job.client || caller == job.freelancer,
            "unauthorized: only client or freelancer can raise a dispute"
        );

        // 3. Job must still be active
        assert!(
            job.status == EscrowStatus::Funded || job.status == EscrowStatus::WorkInProgress,
            "dispute cannot be raised: job is not in active state"
        );

        // 4. Prevent dispute if all funds are already released
        assert!(
            job.released_amount < job.total_amount,
            "dispute cannot be raised: all funds already released"
        );

        // 5. Prevent dispute if deadline has drastically expired (7-day grace period)
        let now: u64 = env.ledger().timestamp();
        let grace_period: u64 = 7u64
            .checked_mul(24)
            .expect("overflow")
            .checked_mul(60)
            .expect("overflow")
            .checked_mul(60)
            .expect("overflow");
        assert!(
            now <= job.expires_at.checked_add(grace_period).expect("overflow"),
            "dispute cannot be raised: deadline has drastically expired"
        );

        // 6. Lock funds by transitioning to Disputed ΓÇö blocks release_funds & release_milestone
        let next_status = EscrowStatus::Disputed;
        job.status.validate_transition(&next_status)?;
        job.status = next_status;
        job.dispute_deadline = now
            .checked_add(Self::DISPUTE_RESOLUTION_WINDOW)
            .ok_or(EscrowError::ArithmeticError)?;
        log!(&env, "raise_dispute: job {}", job_id);
        // 6. Lock funds by transitioning to Disputed — blocks release_funds & release_milestone
        job.status = EscrowStatus::Disputed;
        env.storage().persistent().set(&key, &job);

        // 7. Emit DisputeRaised event for backend / AI Judge to consume
        let mut released_count = 0u32;
        for m in job.milestones.iter() {
            if m.status == MilestoneStatus::Released {
                released_count = released_count.checked_add(1).ok_or(EscrowError::ArithmeticError)?;
                released_count = released_count.checked_add(1).expect("overflow");
            }
        }

        let event_data = DisputeRaisedEvent {
            job_id,
            initiator: caller,
            milestones_released: released_count,
            milestones_total: job.milestones.len(),
            raised_at: now,
        };
        env.events()
            .publish(("escrow", "DisputeRaised"), event_data);
    }

    /// Agent Judge resolves dispute -- splits funds by explicit amounts.
    /// `payee_amount`: Amount to pay to the freelancer (payee).
    /// `payer_amount`: Amount to return to the client (payer).
    pub fn resolve_dispute(env: Env, job_id: u64, payee_amount: i128, payer_amount: i128) {
        let config: ContractConfig = env
            .storage()
            .instance()
            .get(&DataKey::Config)
            .expect("agent judge not set");
        config.agent_judge.require_auth();

        assert!(payee_amount >= 0, "payee_amount must be >= 0");
        assert!(payer_amount >= 0, "payer_amount must be >= 0");

        let key = DataKey::Job(job_id);
        let mut job: EscrowJob = env.storage().persistent().get(&key).expect("job not found");
        assert!(job.status == EscrowStatus::Disputed, "job not disputed");

        let remaining = job
            .total_amount
            .checked_sub(job.released_amount)
            .expect("overflow");
        let total_payout = payee_amount.checked_add(payer_amount).expect("overflow");
        assert!(total_payout <= remaining, "payout exceeds remaining funds");

        let token_client = token::Client::new(&env, &job.token);
        let mut freelancer_amount = payee_amount;

        if let Some(treasury_config) = env.storage().instance().get::<_, TreasuryConfig>(&DataKey::Treasury) {
            let fee = payee_amount
                .checked_mul(treasury_config.fee_bps as i128)
                .expect("overflow")
                .checked_div(10000)
                .expect("overflow");

            if fee > 0 {
                freelancer_amount = payee_amount
                    .checked_sub(fee)
                    .expect("overflow");

                token_client.transfer(
                    &env.current_contract_address(),
                    &treasury_config.routing_address,
                    &fee,
                );
            }
        }

        if freelancer_amount > 0 {
            token_client.transfer(
                &env.current_contract_address(),
                &job.freelancer,
                &freelancer_amount,
            );
        }
        if payer_amount > 0 {
            token_client.transfer(&env.current_contract_address(), &job.client, &payer_amount);
        }

        job.released_amount = job
            .released_amount
            .checked_add(total_payout)
            .expect("overflow");
        job.status = EscrowStatus::Resolved;
        env.storage().persistent().set(&key, &job);
    }

    /// Client recoups funds if freelancer never responded.
    pub fn refund(env: Env, job_id: u64, client: Address) {
        client.require_auth();

        let key = DataKey::Job(job_id);
        let mut job: EscrowJob = env.storage().persistent().get(&key).expect("job not found");

        assert!(
            job.status == EscrowStatus::Funded || job.status == EscrowStatus::WorkInProgress,
            "job not in active state"
        );
        assert!(client == job.client, "only client can refund");

        let remaining = job
            .total_amount
            .checked_sub(job.released_amount)
            .expect("overflow");
        if remaining > 0 {
            let token_client = token::Client::new(&env, &job.token);
            token_client.transfer(&env.current_contract_address(), &job.client, &remaining);
        }

        job.released_amount = job.total_amount;
        job.status = EscrowStatus::Refunded;
        env.storage().persistent().set(&key, &job);
    }

    pub fn get_job(env: Env, job_id: u64) -> EscrowJob {
        env.storage()
            .persistent()
            .get(&DataKey::Job(job_id))
            .expect("job not found")
    }

    /// Requirement [SC-ESC-019]: Dynamic Storage Allocation Recouping (State De-allocation).
    ///
    /// Soroban persistent storage incurs ongoing rent fees proportional to the byte size
    /// of each ledger entry.  Once an escrow job reaches a terminal state, all token
    /// transfers are complete and the on-chain `EscrowJob` record serves no further
    /// functional purpose.  This function allows either party to explicitly de-allocate
    /// the storage entry, recouping the associated ledger rent budget.
    ///
    /// **De-allocation scope** ([SC-ESC-019]):
    /// - Removes the `Job(job_id)` persistent entry (the primary `EscrowJob` struct).
    /// - If a `MultisigConfig(job_id)` entry was written during setup, it is also removed
    ///   in the same call to prevent orphaned storage keys.
    ///
    /// **Safety invariants**:
    /// - Only the client or freelancer (authenticated via `env.require_auth`) may trigger
    ///   cleanup — preventing griefing by third parties.
    /// - The job must be in a terminal state: `Completed`, `Refunded`, or `Resolved`.
    ///   Active jobs (`Setup`, `Funded`, `WorkInProgress`, `Disputed`) are rejected with
    ///   `InvalidState` (error code `#6`).
    /// - A `checked_sub` guard verifies `remaining == 0` before removal.  If funds are
    ///   somehow still outstanding (which should be impossible in a terminal state), the
    ///   call is rejected rather than silently discarding live funds.
    ///
    /// # Errors
    /// - `JobNotFound` — no persistent record for `job_id`.
    /// - `Unauthorized` — caller is neither client nor freelancer.
    /// - `InvalidState` — job is not in a terminal state, or remaining balance > 0.
    /// - `ArithmeticError` — underflow when computing `total_amount - released_amount`.
    pub fn cleanup_job(env: Env, job_id: u64, caller: Address) -> Result<(), EscrowError> {
        // [SC-ESC-019]: Caller must authenticate before triggering de-allocation.
        caller.require_auth();

        let key = DataKey::Job(job_id);
        let job: EscrowJob = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(EscrowError::JobNotFound)?;

        // [SC-ESC-019]: Only the escrow parties (client or freelancer) may trigger cleanup.
        // Third-party callers receive `Unauthorized` (error code #3).
        if !(caller == job.client || caller == job.freelancer) {
            return Err(EscrowError::Unauthorized);
        }

        // [SC-ESC-019]: Terminal state gate — only jobs that have fully concluded
        // (Completed, Refunded, Resolved) may be de-allocated.  Active jobs are blocked
        // to prevent accidental data loss while funds are still in escrow.
        if !(job.status == EscrowStatus::Completed
            || job.status == EscrowStatus::Refunded
            || job.status == EscrowStatus::Resolved)
        {
            return Err(EscrowError::InvalidState);
        }

        // [SC-ESC-019]: Defensive arithmetic check — `checked_sub` prevents underflow
        // and guarantees the outstanding balance is truly zero before removal.
        let remaining = job
            .total_amount
            .checked_sub(job.released_amount)
            .ok_or(EscrowError::ArithmeticError)?;
        if remaining > 0 {
            // This branch should be unreachable in a well-formed terminal state, but is
            // kept as a hard safety guard against any future state-machine bugs.
            return Err(EscrowError::InvalidState);
        }

        // [SC-ESC-019]: Primary de-allocation — remove the EscrowJob ledger entry.
        env.storage().persistent().remove(&key);

        // [SC-ESC-019]: Secondary de-allocation — remove orphaned MultisigConfig if present.
        // This ensures no dangling storage keys are left after job teardown.
        let ms_key = DataKey::MultisigConfig(job_id);
        if env.storage().persistent().has(&ms_key) {
            env.storage().persistent().remove(&ms_key);
        }

        env.events().publish(
            ("escrow", "CleanupJob"),
            (job_id, caller, env.ledger().timestamp()),
        );

        Ok(())
    }

    pub fn get_job(env: Env, job_id: u64) -> Result<EscrowJob, EscrowError> {
        let key = DataKey::Job(job_id);
    pub fn get_escrow_balance(env: Env, job_id: u64) -> i128 {
        let job: EscrowJob = env
            .storage()
            .persistent()
            .get(&DataKey::Job(job_id))
            .expect("job not found");
        job.total_amount
            .checked_sub(job.released_amount)
            .expect("overflow")
    }

    pub fn get_milestone(env: Env, job_id: u64, index: u32) -> Milestone {
        let job: EscrowJob = env
            .storage()
            .persistent()
            .get(&DataKey::Job(job_id))
            .expect("job not found");
        job.milestones.get(index).expect("milestone not found")
    }

    /// Retrieve the status of all milestones for a given job.
    pub fn get_milestone_status(env: Env, job_id: u64) -> Vec<MilestoneStatus> {
        let job: EscrowJob = env
            .storage()
            .persistent()
            .get(&DataKey::Job(job_id))
            .expect("job not found");
        let mut statuses = Vec::new(&env);
        for m in job.milestones.iter() {
            statuses.push_back(m.status);
        }
        statuses
    }
}

impl EscrowContract {
    fn check_reentrancy(env: &Env, job_id: u64) {
        if env.storage().instance().has(&DataKey::GuardFlag(job_id)) {
            panic!("reentrant");
        }
    }

    fn set_guard(env: &Env, job_id: u64) {
        env.storage()
            .instance()
            .set(&DataKey::GuardFlag(job_id), &true);
    }

    fn clear_guard(env: &Env, job_id: u64) {
        env.storage().instance().remove(&DataKey::GuardFlag(job_id));
    }

    fn release_milestone_internal(
        env: &Env,
        job_id: u64,
        job: &mut EscrowJob,
        milestone_index: u32,
    ) {
        let mut milestone = job.milestones.get(milestone_index).expect("invalid");
        milestone.status = MilestoneStatus::Released;
        job.milestones.set(milestone_index, milestone.clone());

        job.released_amount = job
            .released_amount
            .checked_add(milestone.amount)
            .expect("overflow");
        job.status = EscrowStatus::WorkInProgress;

        Self::payout_with_fee(&env, job, milestone.amount);

        if job.released_amount == job.total_amount {
            job.status = EscrowStatus::Completed;
        }

        log!(
            &env,
            "expire_dispute: job {} refunded {}",
            job_id,
            remaining
        );
env.storage().persistent().set(&key, &job);
Self::bump_job_ttl(&env, &key);

exit_reentrancy_guard(&env);
        env.events().publish(
            ("escrow", "DisputeExpired"),
            DisputeExpiredEvent {
                job_id,
                refunded_to: job.client,
                amount: remaining,
                expired_at: now,
            },
        );

        Ok(())
    }

    /// Retrieve the status of all milestones for a given job.
    pub fn get_milestone_status(
        env: Env,
        job_id: u64,
    ) -> Result<Vec<MilestoneStatus>, EscrowError> {
        let key = DataKey::Job(job_id);
        let job: EscrowJob = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(EscrowError::JobNotFound)?;
        Self::bump_job_ttl(&env, &key);
        let mut statuses = Vec::new(&env);
        for m in job.milestones.iter() {
            statuses.push_back(m.status);
        }
        Ok(statuses)
    }

    /// Retrieve the multisig configuration for a given job.
    pub fn get_multisig_config(env: Env, job_id: u64) -> Result<MultisigConfig, EscrowError> {
        let config_key = DataKey::MultisigConfig(job_id);
        let config: MultisigConfig = env
            .storage()
            .persistent()
            .get(&config_key)
            .ok_or(EscrowError::InvalidInput)?;
        Self::bump_job_ttl(&env, &config_key);
        Ok(config)
    }

    /// Read-only helper exposing active escrow configuration.
    pub fn get_escrow_config(env: Env) -> Result<(Address, Address, Option<Address>), EscrowError> {
        let config: ContractConfig = env
            .storage()
            .instance()
            .get(&DataKey::Config)
            .ok_or(EscrowError::NotInitialized)?;
        let job_registry: Option<Address> = env.storage().instance().get(&DataKey::JobRegistry);
        Self::bump_instance_ttl(&env);
        Ok((config.admin, config.agent_judge, job_registry))
    }

    /// Read-only helper exposing unreleased escrow balance for a job.
    pub fn get_remaining_balance(env: Env, job_id: u64) -> Result<i128, EscrowError> {
        let key = DataKey::Job(job_id);
        let job: EscrowJob = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(EscrowError::JobNotFound)?;
        Self::bump_job_ttl(&env, &key);
        Self::checked_sub_i128(&env, job.total_amount, job.released_amount)
    }

    /// Configure multisig for a job. Only callable by client during Setup phase.
    pub fn configure_multisig(
        env: Env,
        job_id: u64,
        signers: Vec<Address>,
        required_signatures: u32,
    ) -> Result<(), EscrowError> {
        let key = DataKey::Job(job_id);
        let mut job: EscrowJob = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(EscrowError::JobNotFound)?;
        Self::bump_job_ttl(&env, &key);

        job.client.require_auth();

        if job.status != EscrowStatus::Setup {
            return Err(EscrowError::InvalidState);
        }

        if signers.is_empty() || required_signatures == 0 {
            return Err(EscrowError::InvalidInput);
        }

        if required_signatures > signers.len() {
            return Err(EscrowError::InvalidInput);
        }

        let config = MultisigConfig {
            signers: signers.clone(),
            required_signatures,
            current_signatures: Vec::new(&env),
        };

        env.storage()
            .persistent()
            .set(&DataKey::MultisigConfig(job_id), &config);

        job.requires_multisig = true;
        env.storage().persistent().set(&key, &job);
        Self::bump_job_ttl(&env, &key);

        env.events().publish(
            ("escrow", "MultisigConfigured"),
            MultisigConfiguredEvent {
                job_id,
                required_signatures,
                total_signers: signers.len(),
                configured_at: env.ledger().timestamp(),
            },
        );

        Ok(())
    }

    /// Sign a multisig job. Callable by any configured signer.
    pub fn sign_multisig(env: Env, job_id: u64, signer: Address) -> Result<(), EscrowError> {
        signer.require_auth();

        let key = DataKey::Job(job_id);
        let job: EscrowJob = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(EscrowError::JobNotFound)?;
        Self::bump_job_ttl(&env, &key);

        if !job.requires_multisig {
            return Err(EscrowError::InvalidInput);
        }

        let config_key = DataKey::MultisigConfig(job_id);
        let mut config: MultisigConfig = env
            .storage()
            .persistent()
            .get(&config_key)
            .ok_or(EscrowError::InvalidInput)?;

        // Check if signer is authorized
        let mut is_signer = false;
        for s in config.signers.iter() {
            if s == signer {
                is_signer = true;
                break;
            }
        }
        if !is_signer {
            return Err(EscrowError::Unauthorized);
        }

        // Check if already signed
        for s in config.current_signatures.iter() {
            if s == signer {
                return Err(EscrowError::AlreadySigned);
            }
        }

        config.current_signatures.push_back(signer.clone());
        env.storage().persistent().set(&config_key, &config);
        Self::bump_job_ttl(&env, &config_key);

        env.events().publish(
            ("escrow", "MultisigSigned"),
            MultisigSignedEvent {
                job_id,
                signer,
                signature_count: config.current_signatures.len(),
                signed_at: env.ledger().timestamp(),
            },
        );

        Ok(())
    }

    /// Check if a multisig job has enough signatures
    pub fn check_multisig_ready(env: Env, job_id: u64) -> Result<bool, EscrowError> {
        let key = DataKey::Job(job_id);
        let job: EscrowJob = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(EscrowError::JobNotFound)?;

        if !job.requires_multisig {
            return Ok(true);
        }

        let config_key = DataKey::MultisigConfig(job_id);
        let config: MultisigConfig = env
            .storage()
            .persistent()
            .get(&config_key)
            .ok_or(EscrowError::InvalidInput)?;

        Ok(config.current_signatures.len() >= config.required_signatures)
    }

    // ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
    // SC-ESC-001: Admin fee splitting
    // ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

    /// Admin configures the platform treasury and fee (in basis points).
    /// Once set, milestone releases route `fee_bps` of each payout to the
    /// treasury and the remainder to the freelancer.
    pub fn set_fee_config(
        env: Env,
        treasury: Address,
        fee_bps: u32,
    ) -> Result<(), EscrowError> {
    pub fn set_fee_config(env: Env, treasury: Address, fee_bps: u32) -> Result<(), EscrowError> {
        let config: ContractConfig = env
            .storage()
            .instance()
            .get(&DataKey::Config)
            .ok_or(EscrowError::NotInitialized)?;
        let admin = config.admin;
        admin.require_auth();

        if fee_bps > MAX_FEE_BPS {
            return Err(EscrowError::FeeTooHigh);
        }

        env.storage().instance().set(&DataKey::Treasury, &treasury);
        env.storage().instance().set(&DataKey::FeeBps, &fee_bps);
        Self::bump_instance_ttl(&env);

        env.events().publish(
            ("escrow", "FeeConfigUpdated"),
            FeeConfigUpdatedEvent {
                treasury,
                fee_bps,
                updated_at: env.ledger().timestamp(),
            },
        );

        Ok(())
    }

    /// Returns the active platform fee in basis points (0 when unset).
    pub fn get_fee_bps(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::FeeBps)
            .unwrap_or(0)
    }

    /// Returns the configured treasury address, if any.
    pub fn get_treasury(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::Treasury)
    }

    fn fee_bps(env: &Env) -> u32 {
        env.storage()
            .instance()
            .get::<_, u32>(&DataKey::FeeBps)
            .unwrap_or(0u32)
        env.storage().persistent().set(&DataKey::Job(job_id), job);
    }

    fn payout_with_fee(env: &Env, job: &EscrowJob, amount: i128) {
        let token_client = token::Client::new(env, &job.token);
        let mut freelancer_amount = amount;

        if let Some(treasury_config) = env.storage().instance().get::<_, TreasuryConfig>(&DataKey::Treasury) {
            let fee = amount
                .checked_mul(treasury_config.fee_bps as i128)
                .expect("overflow")
                .checked_div(10000)
                .expect("overflow");

            if fee > 0 {
                freelancer_amount = amount
                    .checked_sub(fee)
                    .expect("overflow");

                token_client.transfer(
                    &env.current_contract_address(),
                    &treasury_config.routing_address,
                    &fee,
                );
            }
        }

        if freelancer_amount > 0 {
            token_client.transfer(
                &env.current_contract_address(),
                &job.freelancer,
                &freelancer_amount,
            );
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{token, Address, Env};

    fn setup_token(env: &Env, admin: &Address) -> Address {
        let contract = env.register_stellar_asset_contract_v2(admin.clone());
        contract.address()
    }

    fn mint(env: &Env, token_addr: &Address, to: &Address) {
        let admin_client = token::StellarAssetClient::new(env, token_addr);
        admin_client.mint(to, &100_000);
    }

    #[test]
    fn test_happy_path_lifecycle() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.add_milestone(&1u64, &3000i128);
        cc.add_milestone(&1u64, &3000i128);
        cc.add_milestone(&1u64, &3000i128);
        cc.deposit(&1u64, &9000i128);

        let tc = token::Client::new(&env, &token_addr);
        assert_eq!(tc.balance(&contract_id), 9000);

        cc.release_milestone(&1u64, &client);
        assert_eq!(tc.balance(&freelancer), 3000);

        cc.release_milestone(&1u64, &client);
        assert_eq!(tc.balance(&freelancer), 6000);

        cc.release_milestone(&1u64, &client);
        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::Completed);
        assert_eq!(tc.balance(&freelancer), 9000);
        assert_eq!(tc.balance(&contract_id), 0);
    }

    #[test]
    fn test_variable_milestone_amounts() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);

        // 3 distinct milestones with different amounts
        cc.add_milestone(&1u64, &2000i128); // 20%
        cc.add_milestone(&1u64, &3000i128); // 30%
        cc.add_milestone(&1u64, &5000i128); // 50%

        cc.deposit(&1u64, &10_000i128);

        let tc = token::Client::new(&env, &token_addr);
        assert_eq!(tc.balance(&contract_id), 10_000);

        // Release first milestone
        cc.release_milestone(&1u64, &client);
        assert_eq!(tc.balance(&freelancer), 2000);

        // Check milestone status
        let statuses = cc.get_milestone_status(&1u64);
        assert_eq!(statuses.get(0).unwrap(), MilestoneStatus::Released);
        assert_eq!(statuses.get(1).unwrap(), MilestoneStatus::Pending);

        // Release second milestone
        cc.release_milestone(&1u64, &client);
        assert_eq!(tc.balance(&freelancer), 5000);

        // Release third milestone
        cc.release_milestone(&1u64, &client);
        assert_eq!(tc.balance(&freelancer), 10_000);

        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::Completed);
    }

    #[test]
    #[should_panic(expected = "already initialized")]
    fn test_double_init() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.initialize(&admin, &agent_judge);
    }

    #[test]
    #[should_panic(expected = "only client can release")]
    fn test_unauthorized_release() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);
        let rando = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.add_milestone(&1u64, &500i128);
        cc.add_milestone(&1u64, &500i128);
        cc.deposit(&1u64, &1000i128);

        cc.release_milestone(&1u64, &rando);
    }

    #[test]
    fn test_dispute_50_50_split() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.add_milestone(&1u64, &2500i128);
        cc.add_milestone(&1u64, &2500i128);
        cc.add_milestone(&1u64, &2500i128);
        cc.add_milestone(&1u64, &2500i128);
        cc.deposit(&1u64, &10_000i128);

        cc.release_milestone(&1u64, &client);
        let tc = token::Client::new(&env, &token_addr);
        assert_eq!(tc.balance(&freelancer), 2500);

        cc.open_dispute(&1u64, &freelancer);
        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::Disputed);

        // 50/50 split of remaining (7500): 3750 to freelancer, 3750 to client
        cc.resolve_dispute(&1u64, &3750i128, &3750i128);
        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::Resolved);
        assert_eq!(tc.balance(&freelancer), 6250);
        assert_eq!(tc.balance(&client), 93750);
    }

    #[test]
    fn test_refund() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.add_milestone(&1u64, &2500i128);
        cc.add_milestone(&1u64, &2500i128);
        cc.deposit(&1u64, &5000i128);

        assert_eq!(
            token::Client::new(&env, &token_addr).balance(&client),
            95_000
        );

        cc.refund(&1u64, &client);
        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::Refunded);
        assert_eq!(
            token::Client::new(&env, &token_addr).balance(&client),
            100_000
        );
    }

    #[test]
    #[should_panic(expected = "sum of milestones must equal total amount")]
    fn test_deposit_with_wrong_total_panics() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.add_milestone(&1u64, &500i128);
        cc.deposit(&1u64, &1000i128); // Should panic as 500 != 1000
    }

    #[test]
    #[should_panic(expected = "no milestones defined")]
    fn test_deposit_no_milestones_panics() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.deposit(&1u64, &1000i128);
    }

    #[test]
    #[should_panic(expected = "job already exists")]
    fn test_double_create_job_panics() {
        let env = Env::default();
        env.mock_all_auths();

        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);
        let token_addr = Address::generate(&env);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
    }

    #[test]
    fn test_exhaustive_release_funds_path() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);

        let total_amount = 10_000i128;
        cc.add_milestone(&1u64, &2500i128);
        cc.add_milestone(&1u64, &2500i128);
        cc.add_milestone(&1u64, &2500i128);
        cc.add_milestone(&1u64, &2500i128);
        cc.deposit(&1u64, &total_amount);

        let tc = token::Client::new(&env, &token_addr);
        assert_eq!(tc.balance(&contract_id), total_amount);

        // Release milestones one by one in arbitrary order
        cc.release_funds(&1u64, &client, &2u32);
        assert_eq!(tc.balance(&freelancer), 2500);

        cc.release_funds(&1u64, &client, &0u32);
        assert_eq!(tc.balance(&freelancer), 5000);

        cc.release_funds(&1u64, &client, &3u32);
        assert_eq!(tc.balance(&freelancer), 7500);

        cc.release_funds(&1u64, &client, &1u32);

        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::Completed);
        assert_eq!(tc.balance(&freelancer), total_amount);
        assert_eq!(tc.balance(&contract_id), 0);
    }

    #[test]
    fn test_raise_dispute_by_client_locks_funds() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.add_milestone(&1u64, &3000i128);
        cc.add_milestone(&1u64, &3000i128);
        cc.add_milestone(&1u64, &3000i128);
        cc.deposit(&1u64, &9000i128);

        cc.raise_dispute(&1u64, &client);

        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::Disputed);
    }

    #[test]
    fn test_reentrancy_protection_panics_on_recursive_release() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.add_milestone(&1u64, &5000i128);
        cc.add_milestone(&1u64, &5000i128);
        cc.deposit(&1u64, &10_000i128);

        env.as_contract(&contract_id, || {
            EscrowContract::set_guard(&env, 1u64);
            assert!(env.storage().instance().has(&DataKey::GuardFlag(1u64)));
            EscrowContract::clear_guard(&env, 1u64);
            assert!(!env.storage().instance().has(&DataKey::GuardFlag(1u64)));
        });

        cc.release_milestone(&1u64, &client);
        env.as_contract(&contract_id, || {
            assert!(!env.storage().instance().has(&DataKey::GuardFlag(1u64)));
        });

        cc.release_milestone(&1u64, &client);
        env.as_contract(&contract_id, || {
            assert!(!env.storage().instance().has(&DataKey::GuardFlag(1u64)));
        });

        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::Completed);
    }

    #[test]
    fn test_reentrancy_protection_release_funds_blocked() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.add_milestone(&1u64, &5000i128);
        cc.add_milestone(&1u64, &5000i128);
        cc.deposit(&1u64, &10_000i128);

        env.as_contract(&contract_id, || {
            EscrowContract::set_guard(&env, 1u64);
            assert!(env.storage().instance().has(&DataKey::GuardFlag(1u64)));
            EscrowContract::clear_guard(&env, 1u64);
            assert!(!env.storage().instance().has(&DataKey::GuardFlag(1u64)));
        });

        cc.release_milestone(&1u64, &client);
        env.as_contract(&contract_id, || {
            assert!(!env.storage().instance().has(&DataKey::GuardFlag(1u64)));
        });

        cc.release_funds(&1u64, &client, &1u32);
        env.as_contract(&contract_id, || {
            assert!(!env.storage().instance().has(&DataKey::GuardFlag(1u64)));
        });

        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::Completed);
    }

    #[test]
    fn test_get_escrow_balance_decreases_on_release() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.add_milestone(&1u64, &2000i128);
        cc.add_milestone(&1u64, &3000i128);
        cc.add_milestone(&1u64, &5000i128);
        cc.deposit(&1u64, &10_000i128);

        assert_eq!(cc.get_escrow_balance(&1u64), 10_000);

        cc.release_milestone(&1u64, &client);
        assert_eq!(cc.get_escrow_balance(&1u64), 8000);

        cc.release_milestone(&1u64, &client);
        assert_eq!(cc.get_escrow_balance(&1u64), 5000);

        cc.release_milestone(&1u64, &client);
        assert_eq!(cc.get_escrow_balance(&1u64), 0);
    }

    #[test]
    fn test_multiple_jobs_isolated() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client_one = Address::generate(&env);
        let freelancer_one = Address::generate(&env);
        let client_two = Address::generate(&env);
        let freelancer_two = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client_one);
        mint(&env, &token_addr, &client_two);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);

        cc.create_job(&1u64, &client_one, &freelancer_one, &token_addr);
        cc.add_milestone(&1u64, &4000i128);
        cc.add_milestone(&1u64, &6000i128);
        cc.deposit(&1u64, &10_000i128);

        cc.create_job(&2u64, &client_two, &freelancer_two, &token_addr);
        cc.add_milestone(&2u64, &1500i128);
        cc.add_milestone(&2u64, &2500i128);
        cc.deposit(&2u64, &4000i128);

        cc.release_milestone(&1u64, &client_one);

        assert_eq!(cc.get_escrow_balance(&1u64), 6000);
        assert_eq!(cc.get_escrow_balance(&2u64), 4000);
        assert_eq!(
            cc.get_milestone(&1u64, &0u32).status,
            MilestoneStatus::Released
        );
        assert_eq!(
            cc.get_milestone(&1u64, &1u32).status,
            MilestoneStatus::Pending
        );
        assert_eq!(
            cc.get_milestone(&2u64, &0u32).status,
            MilestoneStatus::Pending
        );

        cc.release_funds(&2u64, &client_two, &1u32);

        assert_eq!(cc.get_escrow_balance(&1u64), 6000);
        assert_eq!(cc.get_escrow_balance(&2u64), 1500);
        assert_eq!(
            cc.get_milestone(&2u64, &0u32).status,
            MilestoneStatus::Pending
        );
        assert_eq!(
            cc.get_milestone(&2u64, &1u32).status,
            MilestoneStatus::Released
        );

        let tc = token::Client::new(&env, &token_addr);
        assert_eq!(tc.balance(&freelancer_one), 4000);
        assert_eq!(tc.balance(&freelancer_two), 2500);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SC-ESC-016: Enforce Limit Restrictions on Maximum Milestone Partition Counts
    // ─────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_add_milestones_up_to_limit_succeeds() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);

        // Adding exactly MAX_MILESTONES (12) should succeed
        for _ in 0..MAX_MILESTONES {
            cc.add_milestone(&1u64, &100i128);
        }

        let job = cc.get_job(&1u64);
        assert_eq!(job.milestones.len(), MAX_MILESTONES);
    }

    #[test]
    #[should_panic(expected = "Error(Contract, #21)")]
    fn test_add_milestones_limit_exceeded() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);

        // Fill up to the max
        for _ in 0..MAX_MILESTONES {
            cc.add_milestone(&1u64, &100i128);
        }

        // The 13th milestone must fail with MaxMilestonesExceeded (#21)
        cc.add_milestone(&1u64, &100i128);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SC-ESC-013: Verify State Machine Integrity across Multi-Milestone Gigs
    // ─────────────────────────────────────────────────────────────────────────

    /// Full lifecycle: Setup → Funded → WIP → WIP → Completed.
    /// Validates status, released_amount, remaining balance, and milestone
    /// statuses at every intermediate step.
    #[test]
    fn test_multi_milestone_full_lifecycle_state_integrity() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);
        let tc = token::Client::new(&env, &token_addr);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);

        // ── Setup phase ──
        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::Setup);
        assert_eq!(job.milestones.len(), 0);
        assert_eq!(job.total_amount, 0);
        assert_eq!(job.released_amount, 0);

        cc.add_milestone(&1u64, &1000i128);
        cc.add_milestone(&1u64, &2000i128);
        cc.add_milestone(&1u64, &3000i128);
        cc.add_milestone(&1u64, &4000i128);

        let job = cc.get_job(&1u64);
        assert_eq!(job.milestones.len(), 4);
        assert_eq!(job.status, EscrowStatus::Setup);

        // ── Deposit → Funded ──
        cc.deposit(&1u64, &10_000i128);
        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::Funded);
        assert_eq!(job.total_amount, 10_000);
        assert_eq!(job.released_amount, 0);
        assert_eq!(cc.get_escrow_balance(&1u64), 10_000);
        assert_eq!(cc.get_remaining_balance(&1u64), 10_000);
        assert_eq!(tc.balance(&contract_id), 10_000);

        // Verify all milestones are Pending
        let statuses = cc.get_milestone_status(&1u64);
        for i in 0..4u32 {
            assert_eq!(statuses.get(i).unwrap(), MilestoneStatus::Pending);
        }

        // ── Release milestone 0 → WorkInProgress ──
        cc.release_milestone(&1u64, &client);
        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::WorkInProgress);
        assert_eq!(job.released_amount, 1000);
        assert_eq!(cc.get_escrow_balance(&1u64), 9000);
        assert_eq!(cc.get_remaining_balance(&1u64), 9000);
        assert_eq!(tc.balance(&freelancer), 1000);

        let statuses = cc.get_milestone_status(&1u64);
        assert_eq!(statuses.get(0).unwrap(), MilestoneStatus::Released);
        assert_eq!(statuses.get(1).unwrap(), MilestoneStatus::Pending);
        assert_eq!(statuses.get(2).unwrap(), MilestoneStatus::Pending);
        assert_eq!(statuses.get(3).unwrap(), MilestoneStatus::Pending);

        // ── Release milestone 1 → still WorkInProgress ──
        cc.release_milestone(&1u64, &client);
        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::WorkInProgress);
        assert_eq!(job.released_amount, 3000);
        assert_eq!(cc.get_remaining_balance(&1u64), 7000);
        assert_eq!(tc.balance(&freelancer), 3000);

        // ── Release milestone 2 → still WorkInProgress ──
        cc.release_milestone(&1u64, &client);
        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::WorkInProgress);
        assert_eq!(job.released_amount, 6000);
        assert_eq!(cc.get_remaining_balance(&1u64), 4000);
        assert_eq!(tc.balance(&freelancer), 6000);

        // ── Release milestone 3 → Completed ──
        cc.release_milestone(&1u64, &client);
        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::Completed);
        assert_eq!(job.released_amount, 10_000);
        assert_eq!(cc.get_remaining_balance(&1u64), 0);
        assert_eq!(tc.balance(&freelancer), 10_000);
        assert_eq!(tc.balance(&contract_id), 0);

        // All milestones must be Released
        let statuses = cc.get_milestone_status(&1u64);
        for i in 0..4u32 {
            assert_eq!(statuses.get(i).unwrap(), MilestoneStatus::Released);
        }
    }

    /// Out-of-order release_funds (explicit index) with state checks at each step.
    #[test]
    fn test_out_of_order_release_funds_state_integrity() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);
        let tc = token::Client::new(&env, &token_addr);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.add_milestone(&1u64, &1500i128);
        cc.add_milestone(&1u64, &2500i128);
        cc.add_milestone(&1u64, &3000i128);
        cc.add_milestone(&1u64, &3000i128);
        cc.deposit(&1u64, &10_000i128);

        // Release milestone index 3 first (out of order)
        cc.release_funds(&1u64, &client, &3u32);
        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::WorkInProgress);
        assert_eq!(job.released_amount, 3000);
        let statuses = cc.get_milestone_status(&1u64);
        assert_eq!(statuses.get(0).unwrap(), MilestoneStatus::Pending);
        assert_eq!(statuses.get(3).unwrap(), MilestoneStatus::Released);

        // Release milestone index 1
        cc.release_funds(&1u64, &client, &1u32);
        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::WorkInProgress);
        assert_eq!(job.released_amount, 5500);
        assert_eq!(tc.balance(&freelancer), 5500);

        // Release milestone index 0
        cc.release_funds(&1u64, &client, &0u32);
        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::WorkInProgress);
        assert_eq!(job.released_amount, 7000);

        // Release milestone index 2 — final → Completed
        cc.release_funds(&1u64, &client, &2u32);
        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::Completed);
        assert_eq!(job.released_amount, 10_000);
        assert_eq!(tc.balance(&freelancer), 10_000);
        assert_eq!(tc.balance(&contract_id), 0);

        // All Released
        let statuses = cc.get_milestone_status(&1u64);
        for i in 0..4u32 {
            assert_eq!(statuses.get(i).unwrap(), MilestoneStatus::Released);
        }
    }

    /// Dispute raised mid-WIP after partial milestone releases; verifies balance
    /// accounting is correct through dispute resolution.
    #[test]
    fn test_dispute_mid_wip_partial_milestones_balance_integrity() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);
        let tc = token::Client::new(&env, &token_addr);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.add_milestone(&1u64, &2000i128);
        cc.add_milestone(&1u64, &3000i128);
        cc.add_milestone(&1u64, &5000i128);
        cc.deposit(&1u64, &10_000i128);

        // Release first two milestones
        cc.release_milestone(&1u64, &client); // 2000
        cc.release_milestone(&1u64, &client); // 3000
        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::WorkInProgress);
        assert_eq!(job.released_amount, 5000);
        assert_eq!(tc.balance(&freelancer), 5000);

        // Raise dispute with 5000 remaining
        cc.raise_dispute(&1u64, &freelancer);
        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::Disputed);
        assert_eq!(cc.get_remaining_balance(&1u64), 5000);

        // Milestone statuses: first two Released, third Pending
        let statuses = cc.get_milestone_status(&1u64);
        assert_eq!(statuses.get(0).unwrap(), MilestoneStatus::Released);
        assert_eq!(statuses.get(1).unwrap(), MilestoneStatus::Released);
        assert_eq!(statuses.get(2).unwrap(), MilestoneStatus::Pending);

        // Resolve: 60/40 split of remaining 5000
        cc.resolve_dispute(&1u64, &3000i128, &2000i128);
        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::Resolved);
        // Total released: 5000 (milestones) + 5000 (resolution) = 10000
        assert_eq!(job.released_amount, 10_000);
        assert_eq!(tc.balance(&freelancer), 8000);  // 5000 + 3000
        assert_eq!(tc.balance(&client), 92_000);     // 100000 - 10000 + 2000
    }

    /// Cancel brief in WorkInProgress state refunds only the unreleased portion.
    #[test]
    fn test_cancel_brief_wip_refunds_remaining_only() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);
        let tc = token::Client::new(&env, &token_addr);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.add_milestone(&1u64, &2000i128);
        cc.add_milestone(&1u64, &3000i128);
        cc.add_milestone(&1u64, &5000i128);
        cc.deposit(&1u64, &10_000i128);

        // Release first milestone → WIP
        cc.release_milestone(&1u64, &client);
        assert_eq!(tc.balance(&freelancer), 2000);
        assert_eq!(tc.balance(&client), 90_000);

        // Cancel brief — should refund remaining 8000 to client
        cc.cancel_brief(&1u64, &client);
        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::Refunded);
        assert_eq!(job.released_amount, job.total_amount); // fully accounted
        assert_eq!(tc.balance(&client), 98_000);  // 90000 + 8000
        assert_eq!(tc.balance(&freelancer), 2000); // unchanged
        assert_eq!(tc.balance(&contract_id), 0);   // fully drained
    }

    /// Amend milestones mid-WIP, then release amended milestones to Completed.
    /// Validates the state machine remains coherent through amendment.
    #[test]
    fn test_amend_milestones_then_complete_state_integrity() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);
        let tc = token::Client::new(&env, &token_addr);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.add_milestone(&1u64, &2000i128);
        cc.add_milestone(&1u64, &3000i128);
        cc.add_milestone(&1u64, &5000i128);
        cc.deposit(&1u64, &10_000i128);

        // Release first milestone
        cc.release_milestone(&1u64, &client);
        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::WorkInProgress);
        assert_eq!(job.released_amount, 2000);

        // Amend remaining milestones: 3000+5000=8000 → 4000+4000=8000
        let new_amounts = soroban_sdk::vec![&env, 4000i128, 4000i128];
        cc.amend_milestones(&1u64, &new_amounts);

        // Verify structure: 1 Released + 2 new Pending
        let job = cc.get_job(&1u64);
        assert_eq!(job.milestones.len(), 3);
        assert_eq!(job.status, EscrowStatus::WorkInProgress);
        assert_eq!(job.released_amount, 2000);

        let statuses = cc.get_milestone_status(&1u64);
        assert_eq!(statuses.get(0).unwrap(), MilestoneStatus::Released);
        assert_eq!(statuses.get(1).unwrap(), MilestoneStatus::Pending);
        assert_eq!(statuses.get(2).unwrap(), MilestoneStatus::Pending);

        // Release remaining amended milestones
        cc.release_milestone(&1u64, &client);
        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::WorkInProgress);
        assert_eq!(job.released_amount, 6000);
        assert_eq!(tc.balance(&freelancer), 6000);

        cc.release_milestone(&1u64, &client);
        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::Completed);
        assert_eq!(job.released_amount, 10_000);
        assert_eq!(tc.balance(&freelancer), 10_000);
        assert_eq!(tc.balance(&contract_id), 0);
    }

    /// Getter consistency: get_escrow_balance and get_remaining_balance match
    /// across every state transition in a multi-milestone lifecycle.
    #[test]
    fn test_getter_consistency_across_transitions() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.add_milestone(&1u64, &3000i128);
        cc.add_milestone(&1u64, &3000i128);
        cc.add_milestone(&1u64, &4000i128);
        cc.deposit(&1u64, &10_000i128);

        // Both getters must agree at every step
        assert_eq!(cc.get_escrow_balance(&1u64), cc.get_remaining_balance(&1u64));
        assert_eq!(cc.get_escrow_balance(&1u64), 10_000);

        cc.release_milestone(&1u64, &client);
        assert_eq!(cc.get_escrow_balance(&1u64), cc.get_remaining_balance(&1u64));
        assert_eq!(cc.get_escrow_balance(&1u64), 7000);

        cc.release_milestone(&1u64, &client);
        assert_eq!(cc.get_escrow_balance(&1u64), cc.get_remaining_balance(&1u64));
        assert_eq!(cc.get_escrow_balance(&1u64), 4000);

        cc.release_milestone(&1u64, &client);
        assert_eq!(cc.get_escrow_balance(&1u64), cc.get_remaining_balance(&1u64));
        assert_eq!(cc.get_escrow_balance(&1u64), 0);

        // Final state
        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::Completed);
    }

    /// Unauthorized callers are blocked from all state-mutating functions
    /// on a multi-milestone job.
    #[test]
    fn test_unauthorized_state_mutations_blocked_multi_milestone() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);
        let rando = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.add_milestone(&1u64, &5000i128);
        cc.add_milestone(&1u64, &5000i128);
        cc.deposit(&1u64, &10_000i128);

        // Release first milestone to enter WIP
        cc.release_milestone(&1u64, &client);
        assert_eq!(cc.get_job(&1u64).status, EscrowStatus::WorkInProgress);

        // Verify: release_milestone by rando → Unauthorized (#3)
        let result = cc.try_release_milestone(&1u64, &rando);
        assert!(result.is_err());

        // Verify: release_funds by freelancer → Unauthorized (#3)
        let result = cc.try_release_funds(&1u64, &freelancer, &1u32);
        assert!(result.is_err());

        // Verify: refund by freelancer → Unauthorized (#3)
        let result = cc.try_refund(&1u64, &freelancer);
        assert!(result.is_err());

        // Verify: cancel_brief by rando → Unauthorized (#3)
        let result = cc.try_cancel_brief(&1u64, &rando);
        assert!(result.is_err());

        // State is still WIP — no mutation occurred
        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::WorkInProgress);
        assert_eq!(job.released_amount, 5000);
    }

    /// Invalid state transitions are blocked on multi-milestone jobs:
    /// cannot release after dispute, cannot dispute after completion.
    #[test]
    fn test_invalid_transitions_blocked_multi_milestone() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);

        // ── Test 1: Cannot release after dispute ──
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.add_milestone(&1u64, &3000i128);
        cc.add_milestone(&1u64, &7000i128);
        cc.deposit(&1u64, &10_000i128);

        cc.release_milestone(&1u64, &client); // WIP
        cc.raise_dispute(&1u64, &client);      // Disputed
        assert_eq!(cc.get_job(&1u64).status, EscrowStatus::Disputed);

        // release_milestone must fail in Disputed state
        let result = cc.try_release_milestone(&1u64, &client);
        assert!(result.is_err());

        // release_funds must fail in Disputed state
        let result = cc.try_release_funds(&1u64, &client, &1u32);
        assert!(result.is_err());

        // ── Test 2: Cannot dispute after completion ──
        cc.create_job(&2u64, &client, &freelancer, &token_addr);
        cc.add_milestone(&2u64, &5000i128);
        cc.add_milestone(&2u64, &5000i128);
        cc.deposit(&2u64, &10_000i128);

        cc.release_milestone(&2u64, &client);
        cc.release_milestone(&2u64, &client);
        assert_eq!(cc.get_job(&2u64).status, EscrowStatus::Completed);

        // raise_dispute must fail in Completed state
        let result = cc.try_raise_dispute(&2u64, &client);
        assert!(result.is_err());

        // open_dispute must fail in Completed state
        let result = cc.try_open_dispute(&2u64, &client);
        assert!(result.is_err());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SC-ESC-019: Dynamic Storage Allocation Recouping (State De-allocation)
    // ─────────────────────────────────────────────────────────────────────────
    #[test]
    fn test_cleanup_job_completed() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.add_milestone(&1u64, &5000i128);
        cc.deposit(&1u64, &5000i128);
        cc.release_milestone(&1u64, &client);

        assert_eq!(cc.get_job(&1u64).status, EscrowStatus::Completed);

        // cleanup_job by client
        cc.cleanup_job(&1u64, &client);

        // verify it is deleted
        let result = cc.try_get_job(&1u64);
        assert!(result.is_err());
    }

    #[test]
    fn test_cleanup_job_invalid_state() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.add_milestone(&1u64, &5000i128);
        
        // Setup state
        assert_eq!(cc.get_job(&1u64).status, EscrowStatus::Setup);
        let res = cc.try_cleanup_job(&1u64, &client);
        assert!(res.is_err());

        cc.deposit(&1u64, &5000i128);
        // Funded state
        assert_eq!(cc.get_job(&1u64).status, EscrowStatus::Funded);
        let res = cc.try_cleanup_job(&1u64, &client);
        assert!(res.is_err());
    }

    #[test]
    fn test_cleanup_job_unauthorized() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);
        let random = Address::generate(&env);

        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.add_milestone(&1u64, &5000i128);
        cc.deposit(&1u64, &5000i128);
        cc.release_milestone(&1u64, &client);
        
        // Random tries to cleanup
        let res = cc.try_cleanup_job(&1u64, &random);
        assert!(res.is_err());
    }

    // ──────────────────────────────────────────────────────────────────────────────
    // SC-ESC-016: Additional milestone partition count edge-case tests
    // ──────────────────────────────────────────────────────────────────────────────

    /// [SC-ESC-016] Adding a milestone with a zero amount must be rejected with
    /// `InvalidInput` (error code #4).  Zero-value milestones would corrupt the
    /// deposit-vs-milestone-sum invariant enforced by `deposit`.
    #[test]
    #[should_panic(expected = "Error(Contract, #4)")]
    fn test_add_milestone_zero_amount_panics() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);
        let token_addr = setup_token(&env, &admin);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        // Zero amount must be rejected
        cc.add_milestone(&1u64, &0i128);
    }

    /// [SC-ESC-016] Adding a milestone after the job is `Funded` must be rejected with
    /// `InvalidState` (error code #6).  Once deposited, the partition set is locked.
    #[test]
    #[should_panic(expected = "Error(Contract, #6)")]
    fn test_add_milestone_after_deposit_panics() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);
        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.add_milestone(&1u64, &5000i128);
        cc.deposit(&1u64, &5000i128);

        // Adding a milestone after deposit must fail with InvalidState
        cc.add_milestone(&1u64, &1000i128);
    }

    // ──────────────────────────────────────────────────────────────────────────────
    // SC-ESC-013: Additional state machine integrity tests
    // ──────────────────────────────────────────────────────────────────────────────

    /// [SC-ESC-013] `deposit` must reject when no milestones have been added.
    /// Enforces the invariant: funded amount must equal sum of milestone amounts.
    #[test]
    #[should_panic(expected = "Error(Contract, #4)")]
    fn test_state_machine_deposit_with_no_milestones_panics() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);
        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        // No milestones added — deposit must fail with InvalidInput (#4)
        cc.deposit(&1u64, &5000i128);
    }

    /// [SC-ESC-013] A Disputed job cannot be resolved twice.  The first `resolve_dispute`
    /// transitions to `Resolved`; a second call must fail with `InvalidState` (#6).
    #[test]
    #[should_panic(expected = "Error(Contract, #6)")]
    fn test_state_machine_resolve_dispute_twice_panics() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);
        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.add_milestone(&1u64, &6000i128);
        cc.deposit(&1u64, &6000i128);

        cc.raise_dispute(&1u64, &client);
        // First resolution succeeds
        cc.resolve_dispute(&1u64, &6000i128, &0i128);
        assert_eq!(cc.get_job(&1u64).status, EscrowStatus::Resolved);

        // Second resolution must fail — Resolved → Resolved is not a valid transition
        cc.resolve_dispute(&1u64, &0i128, &0i128);
    }

    /// [SC-ESC-013] Verifies that the job transitions from `Funded` directly to `Completed`
    /// (skipping `WorkInProgress`) when a single-milestone job is fully released at once.
    #[test]
    fn test_state_machine_single_milestone_funded_to_completed() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);
        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);
        let tc = token::Client::new(&env, &token_addr);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.add_milestone(&1u64, &10_000i128);
        cc.deposit(&1u64, &10_000i128);

        // Single milestone: Funded → Completed in one release
        let job = cc.get_job(&1u64);
        assert_eq!(job.status, EscrowStatus::Funded);

        cc.release_milestone(&1u64, &client);
        let job = cc.get_job(&1u64);
        // Funded → Completed (single-milestone fast path, no WIP intermediate)
        assert_eq!(job.status, EscrowStatus::Completed);
        assert_eq!(job.released_amount, 10_000);
        assert_eq!(tc.balance(&freelancer), 10_000);
        assert_eq!(tc.balance(&contract_id), 0);
    }

    // ──────────────────────────────────────────────────────────────────────────────
    // SC-ESC-019: Additional storage de-allocation tests
    // ──────────────────────────────────────────────────────────────────────────────

    /// [SC-ESC-019] `cleanup_job` must succeed in the `Refunded` terminal state and
    /// remove the persistent entry so that `get_job` returns `JobNotFound`.
    #[test]
    fn test_cleanup_job_after_refund_succeeds() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);
        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.add_milestone(&1u64, &4000i128);
        cc.deposit(&1u64, &4000i128);

        // Expire lockup, then refund
        let expiry = cc.get_expiry(&1u64);
        env.ledger().with_mut(|li| li.timestamp = expiry + 1);
        cc.refund(&1u64, &client);
        assert_eq!(cc.get_job(&1u64).status, EscrowStatus::Refunded);

        // Cleanup by the client — must succeed
        cc.cleanup_job(&1u64, &client);

        // Storage entry must now be absent
        let result = cc.try_get_job(&1u64);
        assert!(result.is_err());
    }

    /// [SC-ESC-019] `cleanup_job` must succeed in the `Resolved` terminal state and
    /// free both the Job and any associated MultisigConfig ledger entries.
    #[test]
    fn test_cleanup_job_after_resolved_succeeds() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);
        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);
        cc.add_milestone(&1u64, &8000i128);
        cc.deposit(&1u64, &8000i128);

        cc.raise_dispute(&1u64, &client);
        // Resolve fully in favour of freelancer
        cc.resolve_dispute(&1u64, &8000i128, &0i128);
        assert_eq!(cc.get_job(&1u64).status, EscrowStatus::Resolved);

        // Freelancer cleans up
        cc.cleanup_job(&1u64, &freelancer);

        // Storage entry must now be absent
        let result = cc.try_get_job(&1u64);
        assert!(result.is_err());
    }

    /// [SC-ESC-019] Attempting to `cleanup_job` on a non-existent job ID must return
    /// `JobNotFound` (error code #5).
    #[test]
    #[should_panic(expected = "Error(Contract, #5)")]
    fn test_cleanup_job_not_found_panics() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let caller = Address::generate(&env);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        // Job ID 999 was never created
        cc.cleanup_job(&999u64, &caller);
    }

    /// [SC-ESC-019] `cleanup_job` also removes the associated `MultisigConfig` persistent
    /// key when one was configured, leaving no orphaned ledger entries.
    #[test]
    fn test_cleanup_job_also_removes_multisig_config() {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let agent_judge = Address::generate(&env);
        let client = Address::generate(&env);
        let freelancer = Address::generate(&env);
        let signer1 = Address::generate(&env);
        let signer2 = Address::generate(&env);
        let token_addr = setup_token(&env, &admin);
        mint(&env, &token_addr, &client);

        let contract_id = env.register_contract(None, EscrowContract);
        let cc = EscrowContractClient::new(&env, &contract_id);

        cc.initialize(&admin, &agent_judge);
        cc.create_job(&1u64, &client, &freelancer, &token_addr);

        // Configure multisig during Setup
        let signers = soroban_sdk::vec![&env, signer1.clone(), signer2.clone()];
        cc.configure_multisig(&1u64, &signers, &2u32);

        cc.add_milestone(&1u64, &5000i128);
        cc.deposit(&1u64, &5000i128);
        cc.release_milestone(&1u64, &client);
        assert_eq!(cc.get_job(&1u64).status, EscrowStatus::Completed);

        // MultisigConfig must be readable before cleanup
        let config = cc.get_multisig_config(&1u64);
        assert_eq!(config.required_signatures, 2);

        // Cleanup removes both Job and MultisigConfig
        cc.cleanup_job(&1u64, &client);

        // Job is gone
        let job_result = cc.try_get_job(&1u64);
        assert!(job_result.is_err());

        // MultisigConfig is also gone
        let ms_result = cc.try_get_multisig_config(&1u64);
        assert!(ms_result.is_err());
    }
}
