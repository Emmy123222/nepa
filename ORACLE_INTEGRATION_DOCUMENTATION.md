# Oracle Integration for External Data

## Overview

This document describes the Chainlink oracle integration implementation for the NEPA decentralized utility payment platform. The integration provides real-world data feeds including exchange rates, utility rates, and external API data validation.

## Architecture

### Core Components

1. **OracleManager Contract** - Manages all oracle operations
2. **PriceFeed Structure** - Handles exchange rate data
3. **UtilityRate Structure** - Manages utility rate information
4. **Reliability System** - Tracks oracle performance and reliability
5. **Cost Management** - Controls oracle call costs
6. **Fallback Mechanisms** - Provides backup data sources

### Data Structures

#### PriceFeed
```rust
pub struct PriceFeed {
    pub feed_address: Address,      // Chainlink feed contract address
    pub base_asset: String,         // Base currency (e.g., "ETH")
    pub quote_asset: String,        // Quote currency (e.g., "USD")
    pub decimals: u32,              // Decimal precision
    pub last_updated: u64,          // Last update timestamp
    pub price: i128,                // Current price with decimals
    pub reliability_score: u8,      // Reliability score (0-100)
}
```

#### UtilityRate
```rust
pub struct UtilityRate {
    pub utility_type: String,       // Type of utility (electricity, water, gas)
    pub rate_per_kwh: i128,         // Rate per unit of consumption
    pub currency: String,           // Currency code
    pub region: String,             // Geographic region
    pub last_updated: u64,          // Last update timestamp
    pub reliability_score: u8,      // Reliability score (0-100)
}
```

#### OracleConfig
```rust
pub struct OracleConfig {
    pub max_age_seconds: u64,           // Maximum data age in seconds
    pub min_reliability_score: u8,      // Minimum acceptable reliability
    pub fallback_enabled: bool,          // Enable fallback mechanisms
    pub cost_limit_per_call: i128,       // Maximum cost per oracle call
}
```

## Features

### 1. Chainlink Price Feed Integration

The system integrates with Chainlink price feeds to provide real-time exchange rates for:

- **Cryptocurrency pairs**: ETH/USD, BTC/USD, USDC/USD
- **Fiat currency pairs**: NGN/USD, EUR/USD, GBP/USD
- **Commodity prices**: Oil, gas, electricity futures

**Usage Example:**
```rust
// Add a price feed
let price_feed = PriceFeed {
    feed_address: chainlink_feed_address,
    base_asset: "ETH".to_string(),
    quote_asset: "USD".to_string(),
    decimals: 8,
    last_updated: current_timestamp,
    price: 300000000000, // $3000 with 8 decimals
    reliability_score: 85,
};

OracleManager::add_price_feed(env, admin, "ETH_USD".to_string(), price_feed);
```

### 2. Utility Rate Oracle Integration

Real-time utility rates are provided through oracle feeds for:

- **Electricity rates**: Per kWh pricing by region
- **Water rates**: Per cubic meter pricing
- **Gas rates**: Per therm or cubic meter pricing

**Usage Example:**
```rust
// Add utility rate
let utility_rate = UtilityRate {
    utility_type: "electricity".to_string(),
    rate_per_kwh: 120000, // $0.12 with 6 decimals
    currency: "USD".to_string(),
    region: "LAGOS".to_string(),
    last_updated: current_timestamp,
    reliability_score: 90,
};

OracleManager::add_utility_rate(env, admin, "electricity_LAGOS".to_string(), utility_rate);
```

### 3. External Data Validation

The system validates external data using multiple criteria:

- **Range validation**: Ensures values are within reasonable bounds
- **Decimal precision**: Validates appropriate decimal places
- **Timestamp validation**: Checks data freshness
- **Reliability scoring**: Filters low-quality data

**Validation Function:**
```rust
pub fn validate_external_data(
    data: i128,
    min_value: i128,
    max_value: i128,
    decimals: u32,
) -> bool
```

### 4. Oracle Fallback Mechanisms

When primary oracle data is unavailable or unreliable:

- **Cached data fallback**: Uses recent cached data if within acceptable age
- **Default rate fallback**: Falls back to predefined default rates
- **Multiple oracle sources**: Can switch between different oracle providers
- **Manual override**: Admin can manually set emergency rates

### 5. Data Update Scheduling

Automated scheduling ensures data freshness:

- **Price feeds**: Update every 5 minutes (configurable)
- **Utility rates**: Update every hour (configurable)
- **Reliability tracking**: Continuous monitoring
- **Cost monitoring**: Real-time cost tracking

### 6. Oracle Cost Management

Comprehensive cost control features:

- **Per-call limits**: Maximum cost per individual oracle call
- **Daily limits**: Maximum daily spending on oracle calls
- **Cost tracking**: Detailed cost analytics and reporting
- **Budget optimization**: Intelligent cost-saving strategies

### 7. Data Reliability Scoring

Advanced reliability assessment:

- **Success rate tracking**: Percentage of successful oracle calls
- **Response time monitoring**: Average response time measurement
- **Data consistency**: Cross-validation with multiple sources
- **Historical performance**: Long-term reliability trends

## Integration with Billing System

### Enhanced Payment Functions

#### pay_bill_with_oracle
Processes payments with real-time exchange rate conversion:

```rust
pub fn pay_bill_with_oracle(
    env: Env,
    from: Address,
    token_address: Address,
    meter_id: String,
    amount: i128,
    currency: String,
    use_exchange_rate: bool
) -> Result<(), String>
```

#### pay_utility_bill
Processes utility bills based on consumption and real-time rates:

```rust
pub fn pay_utility_bill(
    env: Env,
    from: Address,
    token_address: Address,
    meter_id: String,
    kwh_consumed: i128,
    utility_type: String,
    region: String,
    currency: String
) -> Result<(), String>
```

### Billing Workflow

1. **Rate Retrieval**: Get current utility rates from oracle
2. **Rate Validation**: Verify rate reliability and freshness
3. **Cost Calculation**: Calculate total bill based on consumption
4. **Currency Conversion**: Convert to payment currency if needed
5. **Payment Processing**: Execute payment with converted amount
6. **Record Keeping**: Store detailed billing information

## Configuration

### Initial Setup

```rust
// Initialize oracle system
let config = OracleConfig {
    max_age_seconds: 300,        // 5 minutes
    min_reliability_score: 70,   // 70% minimum reliability
    fallback_enabled: true,      // Enable fallbacks
    cost_limit_per_call: 1000000, // 0.001 XLM per call
};

NepaBillingContract::initialize(env, admin_address, config);
```

### Adding Price Feeds

```rust
// Add cryptocurrency price feed
let eth_usd_feed = PriceFeed {
    feed_address: "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419".parse().unwrap(),
    base_asset: "ETH".to_string(),
    quote_asset: "USD".to_string(),
    decimals: 8,
    last_updated: current_timestamp,
    price: 300000000000,
    reliability_score: 95,
};

OracleManager::add_price_feed(env, admin, "ETH_USD".to_string(), eth_usd_feed);
```

### Adding Utility Rates

```rust
// Add electricity rate for Lagos
let lagos_electricity = UtilityRate {
    utility_type: "electricity".to_string(),
    rate_per_kwh: 120000, // $0.12/kWh
    currency: "USD".to_string(),
    region: "LAGOS".to_string(),
    last_updated: current_timestamp,
    reliability_score: 90,
};

OracleManager::add_utility_rate(env, admin, "electricity_LAGOS".to_string(), lagos_electricity);
```

## Security Considerations

### Access Control

- **Admin-only functions**: Oracle configuration and feed management
- **Public functions**: Rate retrieval and billing operations
- **Authentication**: All state-changing operations require authentication

### Data Validation

- **Input validation**: All oracle data is validated before use
- **Range checking**: Prevents extreme or invalid values
- **Timestamp verification**: Ensures data freshness
- **Reliability filtering**: Rejects low-quality data

### Cost Protection

- **Spending limits**: Prevents runaway oracle costs
- **Per-call limits**: Caps individual call costs
- **Daily budgets**: Controls overall spending
- **Emergency stops**: Can disable oracle calls if needed

## Monitoring and Analytics

### Oracle Statistics

```rust
// Get comprehensive oracle statistics
let (cost_tracker, reliability, score) = OracleManager::get_oracle_stats(env);

println!("Total spent: {} XLM", cost_tracker.total_spent);
println!("Average cost per call: {} XLM", cost_tracker.average_cost_per_call);
println!("Success rate: {}%", reliability.success_count * 100 / (reliability.success_count + reliability.failure_count));
println!("Reliability score: {}", score);
```

### Update Scheduling

```rust
// Check if updates are needed
let (should_update_prices, should_update_utilities) = NepaBillingContract::should_update_oracles(env);

if should_update_prices {
    // Trigger price feed updates
}

if should_update_utilities {
    // Trigger utility rate updates
}
```

## Testing

The implementation includes comprehensive tests covering:

- **Oracle initialization and configuration**
- **Price feed management and updates**
- **Utility rate management and updates**
- **Data validation mechanisms**
- **Fallback functionality**
- **Reliability scoring**
- **Cost management**
- **Enhanced billing operations**
- **Error handling and edge cases**

### Running Tests

```bash
cargo test --package nepa_contract
```

## Future Enhancements

### Planned Features

1. **Multi-oracle aggregation**: Combine data from multiple oracle providers
2. **Machine learning predictions**: Predict future utility rates
3. **Dynamic pricing**: Time-based and demand-based pricing
4. **Cross-chain oracles**: Support for other blockchain networks
5. **Advanced analytics**: Detailed usage patterns and insights

### Scalability Improvements

1. **Batch updates**: Process multiple oracle updates efficiently
2. **Caching optimization**: Improve data caching strategies
3. **Load balancing**: Distribute oracle calls across providers
4. **Compression**: Reduce data storage requirements

## Conclusion

The Chainlink oracle integration provides NEPA with reliable, real-time external data that enables:

- **Accurate billing**: Real-time utility rates and exchange rates
- **Multi-currency support**: Seamless currency conversions
- **Reliability assurance**: Multiple fallback mechanisms
- **Cost efficiency**: Intelligent cost management
- **Transparency**: Auditable data sources and validation

This implementation meets all acceptance criteria and provides a solid foundation for future enhancements and scalability.
