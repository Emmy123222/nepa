#![no_std]
use soroban_sdk::{
    contract, contractimpl, Address, Env, String, symbol_short, Symbol, Vec, Map, 
    storage::Persistent, storage::Instance
};
use soroban_fixed_point_math::FixedPoint;

// Storage keys for oracle data
const ORACLE_PRICE_FEEDS: Symbol = symbol_short!("OP_FEEDS");
const ORACLE_UTILITY_RATES: Symbol = symbol_short!("UT_RATES");
const ORACLE_CONFIG: Symbol = symbol_short!("OR_CONF");
const ORACLE_RELIABILITY: Symbol = symbol_short!("OR_REL");
const ORACLE_COSTS: Symbol = symbol_short!("OR_COST");
const ORACLE_SCHEDULE: Symbol = symbol_short!("OR_SCH");

// Oracle data structures
#[derive(Clone)]
pub struct PriceFeed {
    pub feed_address: Address,
    pub base_asset: String,
    pub quote_asset: String,
    pub decimals: u32,
    pub last_updated: u64,
    pub price: i128,
    pub reliability_score: u8,
}

#[derive(Clone)]
pub struct UtilityRate {
    pub utility_type: String,
    pub rate_per_kwh: i128,
    pub currency: String,
    pub region: String,
    pub last_updated: u64,
    pub reliability_score: u8,
}

#[derive(Clone)]
pub struct OracleConfig {
    pub max_age_seconds: u64,
    pub min_reliability_score: u8,
    pub fallback_enabled: bool,
    pub cost_limit_per_call: i128,
}

#[derive(Clone)]
pub struct OracleReliability {
    pub success_count: u32,
    pub failure_count: u32,
    pub last_success: u64,
    pub last_failure: u64,
    pub average_response_time: u64,
}

#[derive(Clone)]
pub struct OracleCost {
    pub total_spent: i128,
    pub calls_made: u32,
    pub average_cost_per_call: i128,
    pub daily_limit: i128,
    pub daily_spent: i128,
    pub last_reset: u64,
}

#[derive(Clone)]
pub struct UpdateSchedule {
    pub price_feed_interval: u64,
    pub utility_rate_interval: u64,
    pub last_price_update: u64,
    pub last_utility_update: u64,
}

#[contract]
pub struct OracleManager;

#[contractimpl]
impl OracleManager {
    // Initialize oracle configuration
    pub fn initialize_oracle(
        env: Env,
        admin: Address,
        config: OracleConfig,
    ) {
        admin.require_auth();
        
        // Set initial configuration
        env.storage().instance().set(&ORACLE_CONFIG, &config);
        
        // Initialize reliability tracking
        let reliability = OracleReliability {
            success_count: 0,
            failure_count: 0,
            last_success: 0,
            last_failure: 0,
            average_response_time: 0,
        };
        env.storage().instance().set(&ORACLE_RELIABILITY, &reliability);
        
        // Initialize cost tracking
        let cost = OracleCost {
            total_spent: 0,
            calls_made: 0,
            average_cost_per_call: 0,
            daily_limit: 1000000, // 0.001 XLM default
            daily_spent: 0,
            last_reset: env.ledger().timestamp(),
        };
        env.storage().instance().set(&ORACLE_COSTS, &cost);
        
        // Initialize update schedule
        let schedule = UpdateSchedule {
            price_feed_interval: 300, // 5 minutes
            utility_rate_interval: 3600, // 1 hour
            last_price_update: 0,
            last_utility_update: 0,
        };
        env.storage().instance().set(&ORACLE_SCHEDULE, &schedule);
    }

    // Add a new price feed
    pub fn add_price_feed(
        env: Env,
        admin: Address,
        feed_id: String,
        price_feed: PriceFeed,
    ) {
        admin.require_auth();
        
        let mut feeds: Map<String, PriceFeed> = env.storage()
            .persistent()
            .get(&ORACLE_PRICE_FEEDS)
            .unwrap_or_else(|| Map::new(&env));
        
        feeds.set(feed_id, price_feed);
        env.storage().persistent().set(&ORACLE_PRICE_FEEDS, &feeds);
    }

    // Get price feed data
    pub fn get_price_feed(env: Env, feed_id: String) -> Option<PriceFeed> {
        let feeds: Map<String, PriceFeed> = env.storage()
            .persistent()
            .get(&ORACLE_PRICE_FEEDS)?;
        
        feeds.get(feed_id)
    }

    // Update price feed data (simulated oracle call)
    pub fn update_price_feed(
        env: Env,
        feed_id: String,
        new_price: i128,
        timestamp: u64,
    ) -> Result<(), String> {
        let config: OracleConfig = env.storage()
            .instance()
            .get(&ORACLE_CONFIG)
            .ok_or("Oracle not initialized")?;

        // Check if data is too old
        let current_time = env.ledger().timestamp();
        if current_time > timestamp && (current_time - timestamp) > config.max_age_seconds {
            return Err("Data too old".to_string());
        }

        let mut feeds: Map<String, PriceFeed> = env.storage()
            .persistent()
            .get(&ORACLE_PRICE_FEEDS)
            .ok_or("Price feed not found")?;

        let mut feed = feeds.get(feed_id.clone()).ok_or("Feed ID not found")?;
        
        // Update feed data
        feed.price = new_price;
        feed.last_updated = timestamp;
        
        feeds.set(feed_id, feed);
        env.storage().persistent().set(&ORACLE_PRICE_FEEDS, &feeds);
        
        // Update reliability tracking
        Self::update_reliability(env, true, 0);
        
        Ok(())
    }

    // Add utility rate
    pub fn add_utility_rate(
        env: Env,
        admin: Address,
        rate_id: String,
        utility_rate: UtilityRate,
    ) {
        admin.require_auth();
        
        let mut rates: Map<String, UtilityRate> = env.storage()
            .persistent()
            .get(&ORACLE_UTILITY_RATES)
            .unwrap_or_else(|| Map::new(&env));
        
        rates.set(rate_id, utility_rate);
        env.storage().persistent().set(&ORACLE_UTILITY_RATES, &rates);
    }

    // Get utility rate
    pub fn get_utility_rate(env: Env, rate_id: String) -> Option<UtilityRate> {
        let rates: Map<String, UtilityRate> = env.storage()
            .persistent()
            .get(&ORACLE_UTILITY_RATES)?;
        
        rates.get(rate_id)
    }

    // Update utility rate
    pub fn update_utility_rate(
        env: Env,
        rate_id: String,
        new_rate: i128,
        timestamp: u64,
    ) -> Result<(), String> {
        let config: OracleConfig = env.storage()
            .instance()
            .get(&ORACLE_CONFIG)
            .ok_or("Oracle not initialized")?;

        // Check if data is too old
        let current_time = env.ledger().timestamp();
        if current_time > timestamp && (current_time - timestamp) > config.max_age_seconds {
            return Err("Data too old".to_string());
        }

        let mut rates: Map<String, UtilityRate> = env.storage()
            .persistent()
            .get(&ORACLE_UTILITY_RATES)
            .ok_or("Utility rate not found")?;

        let mut rate = rates.get(rate_id.clone()).ok_or("Rate ID not found")?;
        
        // Update rate data
        rate.rate_per_kwh = new_rate;
        rate.last_updated = timestamp;
        
        rates.set(rate_id, rate);
        env.storage().persistent().set(&ORACLE_UTILITY_RATES, &rates);
        
        // Update reliability tracking
        Self::update_reliability(env, true, 0);
        
        Ok(())
    }

    // Validate external data
    pub fn validate_external_data(
        env: Env,
        data: i128,
        min_value: i128,
        max_value: i128,
        decimals: u32,
    ) -> bool {
        // Check if data is within reasonable bounds
        if data < min_value || data > max_value {
            return false;
        }

        // Check if data has appropriate decimal precision
        let divisor = 10_i128.pow(decimals);
        if data % divisor != 0 && decimals > 0 {
            // Allow some flexibility for floating point conversions
            let tolerance = divisor / 100; // 1% tolerance
            if (data % divisor) > tolerance {
                return false;
            }
        }

        true
    }

    // Get fallback data when oracle fails
    pub fn get_fallback_price(env: Env, feed_id: String) -> Option<i128> {
        let config: OracleConfig = env.storage()
            .instance()
            .get(&ORACLE_CONFIG)?;

        if !config.fallback_enabled {
            return None;
        }

        // Implement fallback logic (e.g., use cached data, default rates, etc.)
        let feeds: Map<String, PriceFeed> = env.storage()
            .persistent()
            .get(&ORACLE_PRICE_FEEDS)?;
        
        let feed = feeds.get(feed_id)?;
        
        // Return cached price if available and not too old
        let current_time = env.ledger().timestamp();
        if (current_time - feed.last_updated) <= (config.max_age_seconds * 2) {
            Some(feed.price)
        } else {
            None
        }
    }

    // Update reliability tracking
    fn update_reliability(env: Env, success: bool, response_time: u64) {
        let mut reliability: OracleReliability = env.storage()
            .instance()
            .get(&ORACLE_RELIABILITY)
            .unwrap_or_else(|| OracleReliability {
                success_count: 0,
                failure_count: 0,
                last_success: 0,
                last_failure: 0,
                average_response_time: 0,
            });

        if success {
            reliability.success_count += 1;
            reliability.last_success = env.ledger().timestamp();
        } else {
            reliability.failure_count += 1;
            reliability.last_failure = env.ledger().timestamp();
        }

        // Update average response time
        let total_calls = reliability.success_count + reliability.failure_count;
        if total_calls > 1 {
            reliability.average_response_time = 
                (reliability.average_response_time * (total_calls - 1) + response_time) / total_calls;
        } else {
            reliability.average_response_time = response_time;
        }

        env.storage().instance().set(&ORACLE_RELIABILITY, &reliability);
    }

    // Get reliability score
    pub fn get_reliability_score(env: Env) -> u8 {
        let reliability: OracleReliability = env.storage()
            .instance()
            .get(&ORACLE_RELIABILITY)
            .unwrap_or_else(|| OracleReliability {
                success_count: 0,
                failure_count: 0,
                last_success: 0,
                last_failure: 0,
                average_response_time: 0,
            });

        let total_calls = reliability.success_count + reliability.failure_count;
        if total_calls == 0 {
            return 50; // Neutral score
        }

        let success_rate = (reliability.success_count * 100) / total_calls;
        
        // Factor in response time (lower is better)
        let response_factor = if reliability.average_response_time < 5000 {
            100
        } else if reliability.average_response_time < 10000 {
            75
        } else if reliability.average_response_time < 30000 {
            50
        } else {
            25
        };

        // Calculate final score (0-100)
        let final_score = (success_rate + response_factor) / 2;
        (final_score as u8).min(100)
    }

    // Track oracle costs
    pub fn track_oracle_cost(env: Env, cost: i128) -> Result<(), String> {
        let mut cost_tracker: OracleCost = env.storage()
            .instance()
            .get(&ORACLE_COSTS)
            .ok_or("Cost tracking not initialized")?;

        let config: OracleConfig = env.storage()
            .instance()
            .get(&ORACLE_CONFIG)
            .ok_or("Oracle not initialized")?;

        // Check if cost exceeds limit per call
        if cost > config.cost_limit_per_call {
            return Err("Cost exceeds limit per call".to_string());
        }

        // Reset daily tracking if needed
        let current_time = env.ledger().timestamp();
        let days_since_reset = (current_time - cost_tracker.last_reset) / 86400; // seconds in a day
        if days_since_reset > 0 {
            cost_tracker.daily_spent = 0;
            cost_tracker.last_reset = current_time;
        }

        // Check daily limit
        if cost_tracker.daily_spent + cost > cost_tracker.daily_limit {
            return Err("Daily cost limit exceeded".to_string());
        }

        // Update cost tracking
        cost_tracker.total_spent += cost;
        cost_tracker.daily_spent += cost;
        cost_tracker.calls_made += 1;
        
        if cost_tracker.calls_made > 0 {
            cost_tracker.average_cost_per_call = cost_tracker.total_spent / cost_tracker.calls_made as i128;
        }

        env.storage().instance().set(&ORACLE_COSTS, &cost_tracker);
        Ok(())
    }

    // Check if update is needed
    pub fn should_update_price_feeds(env: Env) -> bool {
        let schedule: UpdateSchedule = env.storage()
            .instance()
            .get(&ORACLE_SCHEDULE)
            .unwrap_or_else(|| UpdateSchedule {
                price_feed_interval: 300,
                utility_rate_interval: 3600,
                last_price_update: 0,
                last_utility_update: 0,
            });

        let current_time = env.ledger().timestamp();
        current_time >= (schedule.last_price_update + schedule.price_feed_interval)
    }

    // Check if utility rates update is needed
    pub fn should_update_utility_rates(env: Env) -> bool {
        let schedule: UpdateSchedule = env.storage()
            .instance()
            .get(&ORACLE_SCHEDULE)
            .unwrap_or_else(|| UpdateSchedule {
                price_feed_interval: 300,
                utility_rate_interval: 3600,
                last_price_update: 0,
                last_utility_update: 0,
            });

        let current_time = env.ledger().timestamp();
        current_time >= (schedule.last_utility_update + schedule.utility_rate_interval)
    }

    // Update schedule timestamps
    pub fn mark_price_feeds_updated(env: Env) {
        let mut schedule: UpdateSchedule = env.storage()
            .instance()
            .get(&ORACLE_SCHEDULE)
            .unwrap_or_else(|| UpdateSchedule {
                price_feed_interval: 300,
                utility_rate_interval: 3600,
                last_price_update: 0,
                last_utility_update: 0,
            });

        schedule.last_price_update = env.ledger().timestamp();
        env.storage().instance().set(&ORACLE_SCHEDULE, &schedule);
    }

    pub fn mark_utility_rates_updated(env: Env) {
        let mut schedule: UpdateSchedule = env.storage()
            .instance()
            .get(&ORACLE_SCHEDULE)
            .unwrap_or_else(|| UpdateSchedule {
                price_feed_interval: 300,
                utility_rate_interval: 3600,
                last_price_update: 0,
                last_utility_update: 0,
            });

        schedule.last_utility_updated = env.ledger().timestamp();
        env.storage().instance().set(&ORACLE_SCHEDULE, &schedule);
    }

    // Get oracle statistics
    pub fn get_oracle_stats(env: Env) -> (OracleCost, OracleReliability, u8) {
        let cost: OracleCost = env.storage()
            .instance()
            .get(&ORACLE_COSTS)
            .unwrap_or_else(|| OracleCost {
                total_spent: 0,
                calls_made: 0,
                average_cost_per_call: 0,
                daily_limit: 1000000,
                daily_spent: 0,
                last_reset: env.ledger().timestamp(),
            });

        let reliability: OracleReliability = env.storage()
            .instance()
            .get(&ORACLE_RELIABILITY)
            .unwrap_or_else(|| OracleReliability {
                success_count: 0,
                failure_count: 0,
                last_success: 0,
                last_failure: 0,
                average_response_time: 0,
            });

        let score = Self::get_reliability_score(env);

        (cost, reliability, score)
    }
}
