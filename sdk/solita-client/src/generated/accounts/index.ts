export * from './AuthorityAccount';
export * from './FeeRecordAccount';
export * from './ProtocolConfigAccount';
export * from './SessionAccount';
export * from './TreasuryShardAccount';
export * from './WalletAccount';

import { WalletAccount } from './WalletAccount'
import { AuthorityAccount } from './AuthorityAccount'
import { SessionAccount } from './SessionAccount'
import { ProtocolConfigAccount } from './ProtocolConfigAccount'
import { FeeRecordAccount } from './FeeRecordAccount'
import { TreasuryShardAccount } from './TreasuryShardAccount'

export const accountProviders = { WalletAccount, AuthorityAccount, SessionAccount, ProtocolConfigAccount, FeeRecordAccount, TreasuryShardAccount }