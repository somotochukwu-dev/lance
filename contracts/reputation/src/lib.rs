#![no_std]

use soroban_sdk::{
    contract, contractimpl, contracttype, Address, Bytes, Env, IntoVal, Symbol, Vec,
};

const SCORE_MIN: i32 = 0;
const SCORE_MAX: i32 = 10_000;
const INITIAL_SCORE: i32 = 5_000;
const RATING_SCALE: i32 = 1_000;
const FULL_VALIDATOR_STAKE: i128 = 1_000_000;
const MAX_VALIDATOR_DELTA_BPS: i32 = 2_000;
const PERSISTENT_TTL_THRESHOLD: u32 = 50_000;
const PERSISTENT_TTL_EXTEND_TO: u32 = 150_000;

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum JobStatus {
    Open,
    InProgress,
    DeliverableSubmitted,
    Completed,
    Disputed,
}

#[contracttype]
#[derive(Clone)]
pub struct JobRecord {
    pub client: Address,
    pub freelancer: Option<Address>,
    pub metadata_hash: Bytes,
    pub budget_stroops: i128,
    pub status: JobStatus,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum Role {
    Client,
    Freelancer,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum BadgeTier {
    None,
    Bronze,
    Silver,
    Gold,
    Platinum,
}

/// Role-scoped reputation profile.
///
/// Ratings are stored as raw review aggregates plus fixed-point averages
/// (1000 = 1.0 stars). Validator staking metrics are accounting-only here;
/// token custody remains the responsibility of the authorized marketplace
/// contract that calls the adjustment routine.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Profile {
    pub address: Address,
    pub role: Role,
    pub badge_tier: BadgeTier,
    pub avg_rating: i32,
    pub completed_jobs: u32,
    pub reputation_score: i32,
    pub total_review_points: i32,
    pub review_count: u32,
    pub validator_stake_total: i128,
    pub validator_adjustments: u32,
    pub last_updated: u64,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ReputationScore {
    pub address: Address,
    pub role: Role,
    pub score: i32,
    pub total_jobs: u32,
    pub total_points: i32,
    pub reviews: u32,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct ValidatorStake {
    pub validator: Address,
    pub target: Address,
    pub role: Role,
    pub staked_amount: i128,
    pub total_adjustment_bps: i32,
    pub adjustment_count: u32,
    pub last_updated: u64,
}

#[contracttype]
pub enum DataKey {
    Score(Address, Role),
    Profile(Address, Role),
    Admin,
    JobRegistry,
    Reviewed(u64, Address),
    AuthorizedContract,
    ValidatorStake(Address, Address, Role),
}

#[contract]
pub struct ReputationContract;

mod fixed_point {
    use super::{MAX_VALIDATOR_DELTA_BPS, RATING_SCALE, SCORE_MAX};

    pub fn average_rating(total_points: i32, count: u32) -> i32 {
        if count == 0 {
            return 0;
        }

        let avg = (total_points as i128)
            .saturating_mul(RATING_SCALE as i128)
            .checked_div(count as i128)
            .unwrap_or(0);
        (avg as i32).clamp(RATING_SCALE, RATING_SCALE * 5)
    }

    pub fn rating_to_score(avg_rating: i32) -> i32 {
        avg_rating.saturating_mul(2).clamp(0, SCORE_MAX)
    }

    pub fn apply_decay(initial_score: i32, periods_elapsed: u32) -> i32 {
        let mut result = initial_score.clamp(0, SCORE_MAX) as i128;
        for _ in 0..periods_elapsed.min(100) {
            result = result.saturating_mul(990).checked_div(1000).unwrap_or(0);
        }
        (result as i32).clamp(0, SCORE_MAX)
    }

    pub fn stake_weighted_delta(delta_bps: i32, stake_amount: i128, full_stake: i128) -> i32 {
        if stake_amount <= 0 || full_stake <= 0 {
            return 0;
        }

        let bounded_delta = delta_bps.clamp(-MAX_VALIDATOR_DELTA_BPS, MAX_VALIDATOR_DELTA_BPS);
        let stake_bps = stake_amount
            .saturating_mul(10_000)
            .checked_div(full_stake)
            .unwrap_or(0)
            .clamp(0, 10_000);
        let weighted = (bounded_delta as i128)
            .saturating_mul(stake_bps)
            .checked_div(10_000)
            .unwrap_or(0);

        if weighted == 0 && bounded_delta != 0 {
            bounded_delta.signum()
        } else {
            weighted as i32
        }
    }
}

impl ReputationContract {
    fn badge_for(score: i32, completed_jobs: u32) -> BadgeTier {
        if score >= 9_500 && completed_jobs >= 50 {
            BadgeTier::Platinum
        } else if score >= 9_000 && completed_jobs >= 30 {
            BadgeTier::Gold
        } else if score >= 7_500 && completed_jobs >= 15 {
            BadgeTier::Silver
        } else if score >= 6_000 && completed_jobs >= 5 {
            BadgeTier::Bronze
        } else {
            BadgeTier::None
        }
    }

    fn role_from_symbol(env: &Env, role_name: Symbol) -> Role {
        if role_name == Symbol::new(env, "client") {
            Role::Client
        } else if role_name == Symbol::new(env, "freelancer") {
            Role::Freelancer
        } else {
            panic!("unknown role");
        }
    }

    fn load_profile(env: &Env, address: &Address, role: &Role) -> Profile {
        let key = DataKey::Profile(address.clone(), role.clone());
        if env.storage().persistent().has(&key) {
            env.storage().persistent().extend_ttl(
                &key,
                PERSISTENT_TTL_THRESHOLD,
                PERSISTENT_TTL_EXTEND_TO,
            );
        }

        env.storage()
            .persistent()
            .get::<DataKey, Profile>(&key)
            .unwrap_or_else(|| Profile {
                address: address.clone(),
                role: role.clone(),
                badge_tier: BadgeTier::None,
                avg_rating: 0,
                completed_jobs: 0,
                reputation_score: INITIAL_SCORE,
                total_review_points: 0,
                review_count: 0,
                validator_stake_total: 0,
                validator_adjustments: 0,
                last_updated: env.ledger().timestamp(),
            })
    }

    fn save_profile(env: &Env, profile: &Profile) {
        let key = DataKey::Profile(profile.address.clone(), profile.role.clone());
        env.storage().persistent().set(&key, profile);
        env.storage().persistent().extend_ttl(
            &key,
            PERSISTENT_TTL_THRESHOLD,
            PERSISTENT_TTL_EXTEND_TO,
        );
    }

    fn load_score(env: &Env, address: &Address, role: &Role) -> ReputationScore {
        env.storage()
            .persistent()
            .get(&DataKey::Score(address.clone(), role.clone()))
            .unwrap_or_else(|| ReputationScore {
                address: address.clone(),
                role: role.clone(),
                score: INITIAL_SCORE,
                total_jobs: 0,
                total_points: 0,
                reviews: 0,
            })
    }

    fn save_score(env: &Env, score: &ReputationScore) {
        let key = DataKey::Score(score.address.clone(), score.role.clone());
        env.storage().persistent().set(&key, score);
        env.storage().persistent().extend_ttl(
            &key,
            PERSISTENT_TTL_THRESHOLD,
            PERSISTENT_TTL_EXTEND_TO,
        );
    }

    fn require_authorized_contract(env: &Env, caller: &Address) {
        let authorized: Address = env
            .storage()
            .instance()
            .get(&DataKey::AuthorizedContract)
            .expect("authorized contract not set");
        caller.require_auth();
        assert!(*caller == authorized, "unauthorized contract");
    }

    fn apply_score_delta(env: &Env, address: &Address, role: &Role, delta: i32) {
        let mut score = Self::load_score(env, address, role);
        score.score = score.score.saturating_add(delta).clamp(SCORE_MIN, SCORE_MAX);
        score.total_jobs = score.total_jobs.saturating_add(1);
        Self::save_score(env, &score);

        let mut profile = Self::load_profile(env, address, role);
        profile.completed_jobs = score.total_jobs;
        profile.reputation_score = score.score;
        profile.badge_tier = Self::badge_for(profile.reputation_score, profile.completed_jobs);
        profile.last_updated = env.ledger().timestamp();
        Self::save_profile(env, &profile);
    }
}

#[contractimpl]
impl ReputationContract {
    pub fn initialize(env: Env, admin: Address) {
        if env.storage().instance().has(&DataKey::Admin) {
            panic!("already initialized");
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
    }

    pub fn set_job_registry(env: Env, admin: Address, registry: Address) {
        let current_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert!(admin == current_admin, "admin mismatch");
        admin.require_auth();
        env.storage()
            .instance()
            .set(&DataKey::JobRegistry, &registry);
    }

    pub fn set_authorized_contract(env: Env, admin: Address, contract: Address) {
        let current_admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .expect("not initialized");
        assert!(admin == current_admin, "admin mismatch");
        admin.require_auth();
        env.storage()
            .instance()
            .set(&DataKey::AuthorizedContract, &contract);
    }

    pub fn get_profile(env: Env, address: Address, role: Role) -> Profile {
        Self::load_profile(&env, &address, &role)
    }

    pub fn get_badge_tier(env: Env, address: Address) -> BadgeTier {
        Self::load_profile(&env, &address, &Role::Freelancer).badge_tier
    }

    pub fn get_validator_stake(
        env: Env,
        validator: Address,
        target: Address,
        role: Role,
    ) -> ValidatorStake {
        env.storage()
            .persistent()
            .get(&DataKey::ValidatorStake(
                validator.clone(),
                target.clone(),
                role.clone(),
            ))
            .unwrap_or_else(|| ValidatorStake {
                validator,
                target,
                role,
                staked_amount: 0,
                total_adjustment_bps: 0,
                adjustment_count: 0,
                last_updated: env.ledger().timestamp(),
            })
    }

    pub fn submit_rating(env: Env, caller: Address, job_id: u64, target: Address, score: u32) {
        caller.require_auth();
        assert!((1..=5).contains(&score), "score out of range");

        let registry_addr: Address = env
            .storage()
            .instance()
            .get(&DataKey::JobRegistry)
            .expect("job registry not set");
        let get_sym = Symbol::new(&env, "get_job");
        let args = soroban_sdk::vec![&env, job_id.into_val(&env)];
        let job: JobRecord = env.invoke_contract::<JobRecord>(&registry_addr, &get_sym, args);

        assert!(job.status == JobStatus::Completed, "job not completed");

        let target_role = if target == job.client {
            Role::Client
        } else if job.freelancer.clone().is_some_and(|freelancer| target == freelancer) {
            Role::Freelancer
        } else {
            panic!("target not participant");
        };

        let caller_is_client = caller == job.client;
        let caller_is_freelancer = job
            .freelancer
            .clone()
            .is_some_and(|freelancer| caller == freelancer);
        assert!(caller_is_client || caller_is_freelancer, "unauthorized to rate");

        let reviewed_key = DataKey::Reviewed(job_id, caller.clone());
        assert!(
            !env.storage().persistent().has(&reviewed_key),
            "already reviewed"
        );

        let mut profile = Self::load_profile(&env, &target, &target_role);
        profile.total_review_points = profile
            .total_review_points
            .saturating_add(score as i32);
        profile.review_count = profile.review_count.saturating_add(1);
        profile.completed_jobs = profile.completed_jobs.saturating_add(1);
        profile.avg_rating =
            fixed_point::average_rating(profile.total_review_points, profile.review_count);
        profile.reputation_score = fixed_point::rating_to_score(profile.avg_rating);
        profile.badge_tier = Self::badge_for(profile.reputation_score, profile.completed_jobs);
        profile.last_updated = env.ledger().timestamp();
        Self::save_profile(&env, &profile);

        let mut rep = Self::load_score(&env, &target, &target_role);
        rep.total_points = profile.total_review_points;
        rep.reviews = profile.review_count;
        rep.total_jobs = profile.completed_jobs;
        rep.score = profile.reputation_score;
        Self::save_score(&env, &rep);

        env.storage().persistent().set(&reviewed_key, &true);
    }

    pub fn update_score(env: Env, caller: Address, address: Address, role: Role, delta: i32) {
        Self::require_authorized_contract(&env, &caller);
        Self::apply_score_delta(&env, &address, &role, delta);
    }

    pub fn submit_validator_adjustment(
        env: Env,
        caller: Address,
        validator: Address,
        target: Address,
        role: Role,
        delta_bps: i32,
        stake_amount: i128,
    ) -> i32 {
        Self::require_authorized_contract(&env, &caller);
        validator.require_auth();
        assert!(stake_amount > 0, "stake must be positive");

        let effective_delta =
            fixed_point::stake_weighted_delta(delta_bps, stake_amount, FULL_VALIDATOR_STAKE);
        Self::apply_score_delta(&env, &target, &role, effective_delta);

        let key = DataKey::ValidatorStake(validator.clone(), target.clone(), role.clone());
        let mut stake = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| ValidatorStake {
                validator,
                target: target.clone(),
                role: role.clone(),
                staked_amount: 0,
                total_adjustment_bps: 0,
                adjustment_count: 0,
                last_updated: env.ledger().timestamp(),
            });
        stake.staked_amount = stake.staked_amount.saturating_add(stake_amount);
        stake.total_adjustment_bps = stake
            .total_adjustment_bps
            .saturating_add(effective_delta)
            .clamp(-SCORE_MAX, SCORE_MAX);
        stake.adjustment_count = stake.adjustment_count.saturating_add(1);
        stake.last_updated = env.ledger().timestamp();
        env.storage().persistent().set(&key, &stake);

        let mut profile = Self::load_profile(&env, &target, &role);
        profile.validator_stake_total = profile
            .validator_stake_total
            .saturating_add(stake_amount);
        profile.validator_adjustments = profile.validator_adjustments.saturating_add(1);
        Self::save_profile(&env, &profile);

        effective_delta
    }

    pub fn slash(env: Env, caller: Address, address: Address, role: Role, _reason: Symbol) {
        Self::require_authorized_contract(&env, &caller);
        let current = Self::load_score(&env, &address, &role);
        let decayed = fixed_point::apply_decay(current.score, 20);
        let delta = decayed.saturating_sub(current.score).min(-1);
        Self::apply_score_delta(&env, &address, &role, delta);
    }

    pub fn get_score(env: Env, address: Address, role: Role) -> ReputationScore {
        Self::load_score(&env, &address, &role)
    }

    /// Returns [score_bps, completed_jobs, total_review_points, review_count].
    pub fn get_public_metrics(env: Env, address: Address, role_name: Symbol) -> Vec<i128> {
        let role = Self::role_from_symbol(&env, role_name);
        let rep = Self::load_score(&env, &address, &role);

        let mut metrics = Vec::new(&env);
        metrics.push_back(rep.score as i128);
        metrics.push_back(rep.total_jobs as i128);
        metrics.push_back(rep.total_points as i128);
        metrics.push_back(rep.reviews as i128);
        metrics
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{Address, Env};

    fn setup() -> (Env, Address, Address, Address) {
        let env = Env::default();
        env.mock_all_auths();

        let admin = Address::generate(&env);
        let authorized = Address::generate(&env);
        let contract_id = env.register_contract(None, ReputationContract);
        let client = ReputationContractClient::new(&env, &contract_id);
        client.initialize(&admin);
        client.set_authorized_contract(&admin, &authorized);

        (env, contract_id, admin, authorized)
    }

    #[test]
    fn test_empty_profile_reads_are_safe() {
        let (env, contract_id, _, _) = setup();
        let client = ReputationContractClient::new(&env, &contract_id);
        let address = Address::generate(&env);

        let profile = client.get_profile(&address, &Role::Freelancer);

        assert_eq!(profile.address, address);
        assert_eq!(profile.role, Role::Freelancer);
        assert_eq!(profile.badge_tier, BadgeTier::None);
        assert_eq!(profile.reputation_score, INITIAL_SCORE);
        assert_eq!(profile.completed_jobs, 0);
        assert_eq!(profile.review_count, 0);
        assert_eq!(profile.validator_stake_total, 0);
    }

    #[test]
    fn test_authorized_contract_updates_score_and_badge() {
        let (env, contract_id, _, authorized) = setup();
        let client = ReputationContractClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        for _ in 0..5 {
            client.update_score(&authorized, &target, &Role::Freelancer, &300);
        }

        let score = client.get_score(&target, &Role::Freelancer);
        let profile = client.get_profile(&target, &Role::Freelancer);
        assert_eq!(score.score, 6_500);
        assert_eq!(score.total_jobs, 5);
        assert_eq!(profile.completed_jobs, 5);
        assert_eq!(profile.badge_tier, BadgeTier::Bronze);
        assert_eq!(client.get_badge_tier(&target), BadgeTier::Bronze);
    }

    #[test]
    fn test_authorized_contract_can_be_replaced_by_admin() {
        let (env, contract_id, admin, authorized) = setup();
        let client = ReputationContractClient::new(&env, &contract_id);
        let replacement = Address::generate(&env);
        let target = Address::generate(&env);

        client.set_authorized_contract(&admin, &replacement);

        let old_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.update_score(&authorized, &target, &Role::Freelancer, &100);
        }));
        assert!(old_result.is_err());

        client.update_score(&replacement, &target, &Role::Freelancer, &100);
        assert_eq!(
            client.get_score(&target, &Role::Freelancer).score,
            INITIAL_SCORE + 100
        );
    }

    #[test]
    fn test_direct_score_adjustment_requires_authorized_contract() {
        let (env, contract_id, _, _) = setup();
        let client = ReputationContractClient::new(&env, &contract_id);
        let attacker = Address::generate(&env);
        let target = Address::generate(&env);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.update_score(&attacker, &target, &Role::Freelancer, &2_000);
        }));

        assert!(result.is_err());
        assert_eq!(
            client.get_score(&target, &Role::Freelancer).score,
            INITIAL_SCORE
        );
    }

    #[test]
    fn test_validator_stake_adjustment_is_weighted_and_recorded() {
        let (env, contract_id, _, authorized) = setup();
        let client = ReputationContractClient::new(&env, &contract_id);
        let validator = Address::generate(&env);
        let target = Address::generate(&env);

        let effective = client.submit_validator_adjustment(
            &authorized,
            &validator,
            &target,
            &Role::Freelancer,
            &1_000,
            &500_000,
        );

        assert_eq!(effective, 500);
        assert_eq!(
            client.get_score(&target, &Role::Freelancer).score,
            INITIAL_SCORE + 500
        );

        let stake = client.get_validator_stake(&validator, &target, &Role::Freelancer);
        assert_eq!(stake.staked_amount, 500_000);
        assert_eq!(stake.total_adjustment_bps, 500);
        assert_eq!(stake.adjustment_count, 1);

        let profile = client.get_profile(&target, &Role::Freelancer);
        assert_eq!(profile.validator_stake_total, 500_000);
        assert_eq!(profile.validator_adjustments, 1);
    }

    #[test]
    fn test_validator_adjustment_rejects_unapproved_caller() {
        let (env, contract_id, _, _) = setup();
        let client = ReputationContractClient::new(&env, &contract_id);
        let attacker = Address::generate(&env);
        let validator = Address::generate(&env);
        let target = Address::generate(&env);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.submit_validator_adjustment(
                &attacker,
                &validator,
                &target,
                &Role::Freelancer,
                &1_000,
                &500_000,
            );
        }));

        assert!(result.is_err());
        assert_eq!(
            client.get_score(&target, &Role::Freelancer).score,
            INITIAL_SCORE
        );
    }

    #[test]
    fn test_direct_reviews_from_unverified_public_keys_are_rejected() {
        let (env, contract_id, _, _) = setup();
        let client = ReputationContractClient::new(&env, &contract_id);
        let attacker = Address::generate(&env);
        let target = Address::generate(&env);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.submit_rating(&attacker, &44, &target, &5);
        }));

        assert!(result.is_err());
        assert_eq!(
            client.get_score(&target, &Role::Freelancer).reviews,
            0
        );
    }

    #[test]
    fn test_fixed_point_average_and_decay() {
        assert_eq!(fixed_point::average_rating(15, 3), 5_000);
        assert_eq!(fixed_point::average_rating(9, 3), 3_000);
        assert_eq!(fixed_point::average_rating(0, 0), 0);
        assert_eq!(fixed_point::rating_to_score(5_000), 10_000);
        assert_eq!(fixed_point::apply_decay(10_000, 1), 9_900);
        assert_eq!(fixed_point::apply_decay(10_000, 2), 9_801);
    }

    #[test]
    fn test_get_public_metrics_rejects_unknown_role() {
        let (env, contract_id, _, _) = setup();
        let client = ReputationContractClient::new(&env, &contract_id);
        let target = Address::generate(&env);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            client.get_public_metrics(&target, &Symbol::new(&env, "auditor"));
        }));

        assert!(result.is_err());
    }
}
