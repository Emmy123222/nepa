# Build Instructions

## Prerequisites

Before building the NEPA Oracle Integration contract, ensure you have the following installed:

### Rust Toolchain
```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Verify installation
rustc --version
cargo --version
```

### Soroban CLI
```bash
# Install Soroban CLI
cargo install soroban-cli

# Verify installation
soroban --version
```

## Building the Contract

### 1. Build for Development
```bash
cd nepa-dapp/nepa_contract
cargo build
```

### 2. Build for Release (Optimized)
```bash
cd nepa-dapp/nepa_contract
cargo build --release
```

### 3. Run Tests
```bash
cd nepa-dapp/nepa_contract
cargo test
```

### 4. Generate WASM Contract
```bash
cd nepa-dapp/nepa_contract
cargo build --release --target wasm32-unknown-unknown
```

The compiled WASM file will be located at:
```
target/wasm32-unknown-unknown/release/nepa_contract.wasm
```

## Contract Deployment

### 1. Deploy to Testnet
```bash
# Deploy the contract
soroban contract deploy \
  --wasm target/wasm32-unknown-unknown/release/nepa_contract.wasm \
  --source <your-account> \
  --network testnet

# Note the contract address for later use
```

### 2. Initialize the Contract
```bash
# Initialize with oracle configuration
soroban contract invoke \
  --id <contract-address> \
  --source <admin-account> \
  --network testnet \
  -- initialize \
  --admin <admin-address> \
  --config '{"max_age_seconds":300,"min_reliability_score":70,"fallback_enabled":true,"cost_limit_per_call":1000000}'
```

## Testing the Oracle Integration

### 1. Add a Price Feed
```bash
soroban contract invoke \
  --id <contract-address> \
  --source <admin-address> \
  --network testnet \
  -- add_price_feed \
  --admin <admin-address> \
  --feed_id "ETH_USD" \
  --price_feed '{"feed_address":"<chainlink-feed-address>","base_asset":"ETH","quote_asset":"USD","decimals":8,"last_updated":1640995200,"price":300000000000,"reliability_score":85}'
```

### 2. Add a Utility Rate
```bash
soroban contract invoke \
  --id <contract-address> \
  --source <admin-address> \
  --network testnet \
  -- add_utility_rate \
  --admin <admin-address> \
  --rate_id "electricity_LAGOS" \
  --utility_rate '{"utility_type":"electricity","rate_per_kwh":120000,"currency":"USD","region":"LAGOS","last_updated":1640995200,"reliability_score":90}'
```

### 3. Test Enhanced Billing
```bash
soroban contract invoke \
  --id <contract-address> \
  --source <user-address> \
  --network testnet \
  -- pay_utility_bill \
  --from <user-address> \
  --token_address <token-contract-address> \
  --meter_id "meter123" \
  --kwh_consumed 50000 \
  --utility_type "electricity" \
  --region "LAGOS" \
  --currency "USD"
```

## Oracle Integration Features

### Supported Price Feeds
- **Cryptocurrency**: ETH/USD, BTC/USD, USDC/USD
- **Fiat Currency**: NGN/USD, EUR/USD, GBP/USD
- **Commodities**: Oil, gas, electricity futures

### Supported Utility Rates
- **Electricity**: Per kWh rates by region
- **Water**: Per cubic meter rates
- **Gas**: Per therm/cubic meter rates

### Key Features
- **Real-time data**: 5-minute price feed updates
- **Utility rates**: Hourly updates
- **Reliability scoring**: 0-100 quality assessment
- **Fallback mechanisms**: Multiple backup data sources
- **Cost management**: Per-call and daily spending limits
- **Data validation**: Range and timestamp validation

## Troubleshooting

### Common Issues

1. **Rust not found**: Install Rust using rustup
2. **Soroban CLI not found**: Install with `cargo install soroban-cli`
3. **WASM target not found**: Install with `rustup target add wasm32-unknown-unknown`
4. **Contract deployment fails**: Check account balance and network status
5. **Oracle data not updating**: Verify oracle feed addresses and network connectivity

### Debug Commands

```bash
# Check contract state
soroban contract read \
  --id <contract-address> \
  --network testnet \
  --key ORACLE_CONFIG

# Check oracle statistics
soroban contract invoke \
  --id <contract-address> \
  --source <any-address> \
  --network testnet \
  -- get_oracle_stats
```

## Performance Considerations

### Gas Optimization
- Contract is optimized for minimal gas usage
- Fixed-point arithmetic for precise calculations
- Efficient storage patterns for oracle data

### Cost Management
- Default cost limit: 0.001 XLM per oracle call
- Daily spending limit: Configurable by admin
- Automatic cost tracking and reporting

### Reliability Features
- Minimum reliability score: 70% (configurable)
- Data freshness: 5 minutes for prices, 1 hour for utilities
- Fallback enabled by default

## Security Notes

- Only admin can configure oracle settings
- All oracle data is validated before use
- Cost limits prevent runaway spending
- Fallback mechanisms ensure service continuity

## Next Steps

1. Deploy to testnet and verify functionality
2. Configure real Chainlink feed addresses
3. Set up utility rate data sources
4. Test with real payment scenarios
5. Monitor oracle performance and costs
6. Optimize based on real-world usage
