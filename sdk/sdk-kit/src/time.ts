/**
 * The earliest value accepted as a time: 2020-01-01 in Unix seconds. Session
 * and action expiries are Unix seconds (`Clock::unix_timestamp`), and any slot
 * a cluster has reached is far below this, so a slot passed by mistake — what
 * these fields held before time-based expiry — is caught before a passkey
 * prompt: the program would refuse such a session (3008), and store such an
 * action as one that expired decades ago. A v2 session account holding a value
 * below this was written before time-based expiry, and its expiry is a slot.
 */
export const MIN_UNIX_SECONDS = 1_577_836_800n;
