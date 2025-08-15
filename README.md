# SecretKeeper Smart Contract

A decentralized smart contract for Stacks blockchain that provides secure secret storage with conditional disclosure mechanisms.

## Overview

SecretKeeper creates a protected repository system where sensitive information is stored encrypted and only disclosed when predefined protection conditions are violated. The contract implements a community-driven verification system to prevent abuse while ensuring legitimate disclosures occur when safety is compromised.

## Key Features

- **Encrypted Secret Storage**: Secrets are stored in encrypted form on-chain
- **Conditional Disclosure**: Secrets are only revealed when protection rules are sufficiently violated
- **Community Reporting**: Multiple independent parties can report protection violations
- **Trusted Validation**: Authorized validators verify the legitimacy of violation reports
- **Admin Controls**: Contract administrator can override disclosures in emergency situations
- **Transparency**: All actions are recorded on-chain with timestamps

## Core Components

### Secret Repositories
Each repository contains:
- Encrypted secret data
- Protection rules defining when disclosure should occur
- Alert tracking system
- Creator information and timestamps

### Protection Alert System
- Users report violations of protection rules
- Reports include evidence and violated rule details
- Trusted validators verify alert legitimacy
- Automatic threshold counting triggers disclosure eligibility

## Main Functions

### Public Functions

#### `create-repository`
Creates a new secret repository with encrypted data and protection rules.
- **Parameters**: `encrypted-secret`, `protection-rules`
- **Returns**: Repository ID
- **Access**: Any user

#### `send-alert`
Reports a violation of protection rules for a specific repository.
- **Parameters**: `repository-id`, `violated-rule`, `proof`
- **Returns**: Success confirmation
- **Access**: Any user

#### `validate-alert`
Validates a protection alert (trusted validators only).
- **Parameters**: `repository-id`, `sender`
- **Returns**: Success confirmation  
- **Access**: Trusted validators only

#### `disclose-secret`
Reveals the decrypted secret when sufficient alerts are received.
- **Parameters**: `repository-id`, `decrypted-secret`
- **Returns**: Success confirmation
- **Access**: Repository creator only (when threshold met)

#### `admin-disclose`
Emergency disclosure by contract administrator.
- **Parameters**: `repository-id`, `decrypted-secret`
- **Returns**: Success confirmation
- **Access**: Admin only

### Administrative Functions

#### `grant-validator-access`
Authorizes a new trusted validator.
- **Access**: Admin only

#### `update-alert-threshold`
Updates the minimum number of alerts required for disclosure.
- **Access**: Admin only

### Read-Only Functions

- `get-repository-info`: Retrieve repository details
- `get-alert-details`: View specific alert information
- `get-alert-threshold`: Check current disclosure threshold
- `get-repository-count`: Get total repositories created
- `is-validator-trusted`: Verify validator status

## Usage Flow

1. **Create Repository**: User creates a repository with encrypted secret and protection rules
2. **Monitor Conditions**: Community monitors for violations of protection rules
3. **Report Violations**: Users submit alerts when protection rules are breached
4. **Validate Reports**: Trusted validators verify alert legitimacy
5. **Automatic Disclosure**: When threshold is met, repository creator can disclose the secret
6. **Public Access**: Once disclosed, the secret becomes publicly readable

## Security Considerations

- Secrets should be properly encrypted before storage
- Protection rules should be clearly defined and verifiable
- Only trusted validators should be granted validation permissions
- Emergency admin powers should be used responsibly
- Consider the permanence of blockchain storage before creating repositories

## Error Codes

- `u100`: Admin-only function called by non-admin
- `u101`: Insufficient permissions for operation
- `u102`: Repository not found
- `u103`: Protection conditions not met for disclosure
- `u104`: Secret already disclosed
- `u105`: Insufficient alerts for disclosure threshold

## Configuration

- **Default Alert Threshold**: 3 alerts required for disclosure eligibility
- **Maximum Protection Rules**: 5 rules per repository
- **Maximum Alert Senders**: 10 unique reporters tracked per repository
- **String Limits**: 500 characters for secrets, 300 for evidence, 100 for rules

## Deployment Notes

- Contract deployer becomes the initial administrator
- Alert threshold can be adjusted post-deployment
- Validator permissions can be granted to trusted parties
- All state changes are permanent and publicly visible on the blockchain