# Maven Oracle Contract

A Clarity smart contract for managing decentralized oracles on the Stacks blockchain.

## Core Features

- **Oracle Management**
  - Register new oracles with authorized signers
  - Store oracle data including last value and update height
  - Track total oracle updates

- **Access Control**
  - Owner-managed administrative functions
  - Signer verification for updates
  - Minimum update interval enforcement (10 blocks)

## Data Structure

```clarity
{
  signer: principal,
  last-value: (buff 32),
  last-height: uint
}
```

## Key Functions

### Administrative
- `register-oracle`: Register new oracle with signer
- `update-oracle-signer`: Update oracle's authorized signer
- `remove-oracle`: Remove oracle from system
- `transfer-ownership`: Transfer contract ownership

### Oracle Operations
- `submit-proof`: Submit new oracle value with verification
- `get-oracle-data`: Retrieve oracle data
- `is-oracle-fresh`: Check if oracle data is within age limit
- `get-latest-value`: Get most recent oracle value

## Constants
- Minimum block interval: 10 blocks
- Maximum value age: 1000 blocks
- Error codes: 100-104

## Events
The contract emits events for:
- Oracle registration
- Proof submission
- Signer updates
- Ownership transfers

## Security Notes
- Uses basic tx-sender verification
- Implements minimum update interval
- Requires owner authorization for admin functions
