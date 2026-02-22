#![no_std]
// We added 'Address' and 'token' to the imports
use soroban_sdk::{contract, contractimpl, Address, Env, String, token, symbol_short, Symbol};

mod oracle;
use oracle::{OracleManager, PriceFeed, UtilityRate, OracleConfig};

#[cfg(test)]
mod tests;

#[contract]
pub struct NepaBillingContract;

#[contractimpl]
impl NepaBillingContract {
    
    // Initialize the contract with oracle support
    pub fn initialize(env: Env, admin: Address, oracle_config: OracleConfig) {
        // Initialize oracle manager
        OracleManager::initialize_oracle(env, admin, oracle_config);
    }

    // Enhanced pay_bill with oracle integration
    pub fn pay_bill_with_oracle(
        env: Env, 
        from: Address, 
        token_address: Address, 
        meter_id: String, 
        amount: i128,
        currency: String,
        use_exchange_rate: bool
    ) -> Result<(), String> {
        // 1. Verify the user authorized this payment
        from.require_auth();

        // 2. Get exchange rate if needed
        let mut final_amount = amount;
        if use_exchange_rate {
            let exchange_rate_id = format!("{}_USD", currency);
            let price_feed = OracleManager::get_price_feed(env.clone(), exchange_rate_id)
                .ok_or("Exchange rate not available")?;
            
            // Validate price feed reliability
            let config: OracleConfig = env.storage()
                .instance()
                .get(&symbol_short!("OR_CONF"))
                .ok_or("Oracle not initialized")?;
            
            if price_feed.reliability_score < config.min_reliability_score {
                return Err("Price feed reliability too low".to_string());
            }

            // Convert amount using exchange rate (assuming price is in USD)
            final_amount = (amount * price_feed.price) / (10_i128.pow(price_feed.decimals));
        }

        // 3. Initialize the Token client
        let token_client = token::Client::new(&env, &token_address);

        // 4. Move the tokens from the User to the Contract
        token_client.transfer(&from, &env.current_contract_address(), &final_amount);

        // 5. Update the meter record
        let current_total: i128 = env.storage().persistent().get(&meter_id).unwrap_or(0);
        env.storage().persistent().set(&meter_id, &(current_total + final_amount));

        Ok(())
    }

    // Pay utility bill based on consumption and real-time rates
    pub fn pay_utility_bill(
        env: Env,
        from: Address,
        token_address: Address,
        meter_id: String,
        kwh_consumed: i128,
        utility_type: String,
        region: String,
        currency: String
    ) -> Result<(), String> {
        // 1. Verify authorization
        from.require_auth();

        // 2. Get utility rate
        let rate_id = format!("{}_{}", utility_type, region);
        let utility_rate = OracleManager::get_utility_rate(env.clone(), rate_id)
            .ok_or("Utility rate not available")?;

        // 3. Validate utility rate
        let config: OracleConfig = env.storage()
            .instance()
            .get(&symbol_short!("OR_CONF"))
            .ok_or("Oracle not initialized")?;
        
        if utility_rate.reliability_score < config.min_reliability_score {
            return Err("Utility rate reliability too low".to_string());
        }

        // 4. Calculate bill amount
        let subtotal = kwh_consumed * utility_rate.rate_per_kwh;
        
        // 5. Apply currency conversion if needed
        let mut final_amount = subtotal;
        if utility_rate.currency != currency {
            let exchange_rate_id = format!("{}_{}", utility_rate.currency, currency);
            let price_feed = OracleManager::get_price_feed(env.clone(), exchange_rate_id)
                .ok_or("Exchange rate not available")?;
            
            final_amount = (subtotal * price_feed.price) / (10_i128.pow(price_feed.decimals));
        }

        // 6. Process payment
        let token_client = token::Client::new(&env, &token_address);
        token_client.transfer(&from, &env.current_contract_address(), &final_amount);

        // 7. Update meter record with detailed information
        let billing_key = format!("{}_{}", meter_id, env.ledger().timestamp());
        let billing_data = (kwh_consumed, utility_rate.rate_per_kwh, final_amount, utility_type);
        env.storage().persistent().set(&billing_key, &billing_data);

        Ok(())
    }

    // Original pay_bill function for backward compatibility
    pub fn pay_bill(env: Env, from: Address, token_address: Address, meter_id: String, amount: i128) {
        // 1. Verify the user authorized this payment
        from.require_auth();

        // 2. Initialize the Token client (for XLM or USDC)
        let token_client = token::Client::new(&env, &token_address);

        // 3. Move the tokens from the User to the Contract
        token_client.transfer(&from, &env.current_contract_address(), &amount);

        // 4. Update the meter record (using i128 for larger money values)
        let current_total: i128 = env.storage().persistent().get(&meter_id).unwrap_or(0);
        env.storage().persistent().set(&meter_id, &(current_total + amount));
    }

    pub fn get_total_paid(env: Env, meter_id: String) -> i128 {
        env.storage().persistent().get(&meter_id).unwrap_or(0)
    }

    // Get billing details
    pub fn get_billing_details(env: Env, meter_id: String, timestamp: u64) -> Option<(i128, i128, i128, String)> {
        let billing_key = format!("{}_{}", meter_id, timestamp);
        env.storage().persistent().get(&billing_key)
    }

    // Oracle management functions (delegated to OracleManager)
    pub fn add_price_feed(env: Env, admin: Address, feed_id: String, price_feed: PriceFeed) {
        OracleManager::add_price_feed(env, admin, feed_id, price_feed);
    }

    pub fn update_price_feed(env: Env, feed_id: String, new_price: i128, timestamp: u64) -> Result<(), String> {
        OracleManager::update_price_feed(env, feed_id, new_price, timestamp)
    }

    pub fn get_price_feed(env: Env, feed_id: String) -> Option<PriceFeed> {
        OracleManager::get_price_feed(env, feed_id)
    }

    pub fn add_utility_rate(env: Env, admin: Address, rate_id: String, utility_rate: UtilityRate) {
        OracleManager::add_utility_rate(env, admin, rate_id, utility_rate);
    }

    pub fn update_utility_rate(env: Env, rate_id: String, new_rate: i128, timestamp: u64) -> Result<(), String> {
        OracleManager::update_utility_rate(env, rate_id, new_rate, timestamp)
    }

    pub fn get_utility_rate(env: Env, rate_id: String) -> Option<UtilityRate> {
        OracleManager::get_utility_rate(env, rate_id)
    }

    pub fn get_oracle_stats(env: Env) -> (oracle::OracleCost, oracle::OracleReliability, u8) {
        OracleManager::get_oracle_stats(env)
    }

    pub fn should_update_oracles(env: Env) -> (bool, bool) {
        (
            OracleManager::should_update_price_feeds(env.clone()),
            OracleManager::should_update_utility_rates(env)
        )
    }
}