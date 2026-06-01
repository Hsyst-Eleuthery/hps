CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    public_key TEXT NOT NULL,
    created_at REAL NOT NULL,
    last_login REAL NOT NULL,
    reputation INTEGER DEFAULT 100,
    reputation_credit INTEGER DEFAULT 0,
    client_identifier TEXT,
    disk_quota INTEGER DEFAULT 524288000,
    used_disk_space INTEGER DEFAULT 0,
    last_activity REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS content (
    content_hash TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT,
    mime_type TEXT NOT NULL,
    size INTEGER NOT NULL,
    username TEXT NOT NULL,
    signature TEXT NOT NULL,
    public_key TEXT NOT NULL,
    timestamp REAL NOT NULL,
    file_path TEXT NOT NULL,
    verified INTEGER DEFAULT 0,
    replication_count INTEGER DEFAULT 1,
    last_accessed REAL NOT NULL,
    issuer_server TEXT DEFAULT '',
    issuer_public_key TEXT DEFAULT '',
    issuer_contract_id TEXT DEFAULT '',
    issuer_issued_at REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS dns_records (
    domain TEXT PRIMARY KEY,
    content_hash TEXT NOT NULL,
    username TEXT NOT NULL,
    original_owner TEXT NOT NULL,
    timestamp REAL NOT NULL,
    signature TEXT NOT NULL,
    verified INTEGER DEFAULT 0,
    last_resolved REAL NOT NULL,
    ddns_hash TEXT NOT NULL,
    issuer_server TEXT DEFAULT '',
    issuer_public_key TEXT DEFAULT '',
    issuer_contract_id TEXT DEFAULT '',
    issuer_issued_at REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS api_apps (
    app_name TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    timestamp REAL NOT NULL,
    last_updated REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS network_nodes (
    node_id TEXT PRIMARY KEY,
    address TEXT NOT NULL,
    public_key TEXT NOT NULL,
    username TEXT NOT NULL,
    last_seen REAL NOT NULL,
    reputation INTEGER DEFAULT 100,
    node_type TEXT NOT NULL CHECK(node_type IN ('server', 'client')),
    is_online INTEGER DEFAULT 1,
    client_identifier TEXT,
    connection_count INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS content_availability (
    content_hash TEXT NOT NULL,
    node_id TEXT NOT NULL,
    timestamp REAL NOT NULL,
    is_primary INTEGER DEFAULT 0,
    PRIMARY KEY (content_hash, node_id)
);

CREATE TABLE IF NOT EXISTS server_nodes (
    server_id TEXT PRIMARY KEY,
    address TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    last_seen REAL NOT NULL,
    is_active INTEGER DEFAULT 1,
    reputation INTEGER DEFAULT 100,
    sync_priority INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS server_connections (
    local_server_id TEXT NOT NULL,
    remote_server_id TEXT NOT NULL,
    remote_address TEXT NOT NULL,
    last_ping REAL NOT NULL,
    is_active INTEGER DEFAULT 1,
    PRIMARY KEY (local_server_id, remote_server_id)
);

CREATE TABLE IF NOT EXISTS user_reputations (
    username TEXT PRIMARY KEY,
    reputation INTEGER DEFAULT 100,
    reputation_credit INTEGER DEFAULT 0,
    last_updated REAL NOT NULL,
    client_identifier TEXT,
    violation_count INTEGER DEFAULT 0,
    contract_penalty_base INTEGER
);

CREATE TABLE IF NOT EXISTS content_reports (
    report_id TEXT PRIMARY KEY,
    content_hash TEXT NOT NULL,
    reported_user TEXT NOT NULL,
    reporter TEXT NOT NULL,
    timestamp REAL NOT NULL,
    resolved INTEGER DEFAULT 0,
    resolution_type TEXT
);

CREATE TABLE IF NOT EXISTS server_sync_history (
    server_address TEXT NOT NULL,
    last_sync REAL NOT NULL,
    sync_type TEXT NOT NULL,
    items_count INTEGER DEFAULT 0,
    success INTEGER DEFAULT 1,
    PRIMARY KEY (server_address, sync_type)
);

CREATE TABLE IF NOT EXISTS rate_limits (
    client_identifier TEXT NOT NULL,
    action_type TEXT NOT NULL,
    last_action REAL NOT NULL,
    attempt_count INTEGER DEFAULT 1,
    PRIMARY KEY (client_identifier, action_type)
);

CREATE TABLE IF NOT EXISTS pow_history (
    client_identifier TEXT NOT NULL,
    challenge TEXT NOT NULL,
    target_bits INTEGER NOT NULL,
    timestamp REAL NOT NULL,
    success INTEGER DEFAULT 0,
    solve_time REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS known_servers (
    address TEXT PRIMARY KEY,
    added_date REAL NOT NULL,
    last_connected REAL NOT NULL,
    is_active INTEGER DEFAULT 1
);


CREATE TABLE IF NOT EXISTS client_files (
    client_identifier TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    file_name TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    published INTEGER DEFAULT 0,
    last_sync REAL NOT NULL,
    PRIMARY KEY (client_identifier, content_hash)
);

CREATE TABLE IF NOT EXISTS client_dns_files (
    client_identifier TEXT NOT NULL,
    domain TEXT NOT NULL,
    ddns_hash TEXT NOT NULL,
    last_sync REAL NOT NULL,
    PRIMARY KEY (client_identifier, domain)
);

CREATE TABLE IF NOT EXISTS server_connectivity_log (
    server_address TEXT NOT NULL,
    timestamp REAL NOT NULL,
    protocol_used TEXT NOT NULL,
    success INTEGER DEFAULT 0,
    error_message TEXT,
    response_time REAL DEFAULT 0,
    PRIMARY KEY (server_address, timestamp)
);

CREATE TABLE IF NOT EXISTS dns_owner_changes (
    change_id TEXT PRIMARY KEY,
    domain TEXT NOT NULL,
    previous_owner TEXT NOT NULL,
    new_owner TEXT NOT NULL,
    changer TEXT NOT NULL,
    timestamp REAL NOT NULL,
    change_file_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_app_versions (
    version_id TEXT PRIMARY KEY,
    app_name TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    username TEXT NOT NULL,
    timestamp REAL NOT NULL,
    version_number INTEGER DEFAULT 1,
    FOREIGN KEY (app_name) REFERENCES api_apps(app_name) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS content_redirects (
    old_hash TEXT PRIMARY KEY,
    new_hash TEXT NOT NULL,
    username TEXT NOT NULL,
    redirect_type TEXT NOT NULL,
    timestamp REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS contracts (
    contract_id TEXT PRIMARY KEY,
    action_type TEXT NOT NULL,
    content_hash TEXT,
    domain TEXT,
    username TEXT NOT NULL,
    signature TEXT NOT NULL,
    timestamp REAL NOT NULL,
    verified INTEGER DEFAULT 0,
    issuer_server TEXT DEFAULT '',
    contract_content BLOB NOT NULL,
    FOREIGN KEY (content_hash) REFERENCES content(content_hash) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS contract_violations (
    violation_id TEXT PRIMARY KEY,
    violation_type TEXT NOT NULL,
    content_hash TEXT,
    domain TEXT,
    owner_username TEXT NOT NULL,
    reported_by TEXT NOT NULL,
    timestamp REAL NOT NULL,
    reason TEXT NOT NULL,
    UNIQUE(violation_type, content_hash, domain)
);

CREATE TABLE IF NOT EXISTS contract_certifications (
    cert_id TEXT PRIMARY KEY,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    original_owner TEXT NOT NULL,
    certifier TEXT NOT NULL,
    timestamp REAL NOT NULL,
    UNIQUE(target_type, target_id)
);

CREATE TABLE IF NOT EXISTS issuer_verifications (
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    issuer_server TEXT NOT NULL,
    issuer_public_key TEXT NOT NULL,
    issuer_contract_id TEXT NOT NULL,
    original_owner TEXT NOT NULL,
    status TEXT NOT NULL,
    detail TEXT DEFAULT '',
    last_checked REAL NOT NULL,
    verification_contract_id TEXT DEFAULT '',
    exception_contract_id TEXT DEFAULT '',
    debt_contract_id TEXT DEFAULT '',
    PRIMARY KEY (target_type, target_id)
);

CREATE TABLE IF NOT EXISTS phps_debts (
    debt_id TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    source_contract_id TEXT NOT NULL,
    principal INTEGER NOT NULL,
    payout_total INTEGER NOT NULL,
    reserved_amount INTEGER DEFAULT 0,
    creditor_username TEXT DEFAULT '',
    creditor_public_key TEXT DEFAULT '',
    funding_contract_id TEXT DEFAULT '',
    payout_voucher_id TEXT DEFAULT '',
    status TEXT NOT NULL,
    created_at REAL NOT NULL,
    funded_at REAL DEFAULT 0,
    repaid_at REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS issuer_verification_jobs (
    job_id TEXT PRIMARY KEY,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    request_kind TEXT NOT NULL,
    requester_username TEXT NOT NULL,
    original_owner TEXT NOT NULL,
    issuer_server TEXT NOT NULL,
    issuer_public_key TEXT NOT NULL,
    issuer_contract_id TEXT NOT NULL,
    request_contract_id TEXT DEFAULT '',
    assigned_miner TEXT DEFAULT '',
    status TEXT NOT NULL,
    result_status TEXT DEFAULT '',
    result_detail TEXT DEFAULT '',
    result_contract_id TEXT DEFAULT '',
    timeout_confirm_contract_id TEXT DEFAULT '',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    deadline REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_transfers (
    transfer_id TEXT PRIMARY KEY,
    transfer_type TEXT NOT NULL,
    target_user TEXT NOT NULL,
    original_owner TEXT NOT NULL,
    custody_user TEXT NOT NULL,
    content_hash TEXT,
    domain TEXT,
    app_name TEXT,
    contract_id TEXT,
    status TEXT NOT NULL,
    timestamp REAL NOT NULL,
    requester_user TEXT DEFAULT '',
    request_payload TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS contract_valid_archive (
    archive_id TEXT PRIMARY KEY,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    contract_content BLOB NOT NULL,
    updated_at REAL NOT NULL,
    UNIQUE(target_type, target_id)
);

CREATE TABLE IF NOT EXISTS client_contracts (
    client_identifier TEXT NOT NULL,
    contract_id TEXT NOT NULL,
    content_hash TEXT DEFAULT '',
    domain TEXT DEFAULT '',
    last_sync REAL NOT NULL,
    PRIMARY KEY (client_identifier, contract_id)
);

CREATE TABLE IF NOT EXISTS usage_contract_acceptance (
    username TEXT NOT NULL,
    contract_hash TEXT NOT NULL,
    accepted_at REAL NOT NULL,
    PRIMARY KEY (username, contract_hash)
);

CREATE TABLE IF NOT EXISTS hps_vouchers (
    voucher_id TEXT PRIMARY KEY,
    issuer TEXT NOT NULL,
    owner TEXT NOT NULL,
    value INTEGER NOT NULL,
    reason TEXT NOT NULL,
    issued_at REAL NOT NULL,
    payload TEXT NOT NULL,
    issuer_signature TEXT NOT NULL,
    owner_signature TEXT NOT NULL,
    status TEXT NOT NULL,
    session_id TEXT,
    lineage_root_voucher_id TEXT DEFAULT '',
    lineage_parent_voucher_id TEXT DEFAULT '',
    lineage_parent_hash TEXT DEFAULT '',
    lineage_depth INTEGER DEFAULT 0,
    lineage_origin TEXT DEFAULT '',
    invalidated INTEGER DEFAULT 0,
    last_updated REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS miner_stats (
    username TEXT PRIMARY KEY,
    minted_count INTEGER DEFAULT 0,
    minted_total REAL DEFAULT 0,
    pending_signatures INTEGER DEFAULT 0,
    last_updated REAL NOT NULL,
    banned_until REAL DEFAULT 0,
    ban_reason TEXT
);

CREATE TABLE IF NOT EXISTS miner_debt_entries (
    entry_id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    entry_type TEXT NOT NULL,
    amount INTEGER DEFAULT 0,
    status TEXT NOT NULL,
    created_at REAL NOT NULL,
    resolved_at REAL,
    metadata TEXT
);

CREATE TABLE IF NOT EXISTS monetary_transfers (
    transfer_id TEXT PRIMARY KEY,
    transfer_type TEXT NOT NULL,
    sender TEXT NOT NULL,
    receiver TEXT NOT NULL,
    amount INTEGER NOT NULL,
    created_at REAL NOT NULL,
    status TEXT NOT NULL,
    contract_id TEXT,
    locked_voucher_ids TEXT,
    assigned_miner TEXT,
    deadline REAL,
    miner_deadline REAL,
    fee_amount INTEGER DEFAULT 0,
    selector_fee_amount INTEGER DEFAULT 0,
    fee_source TEXT,
    inter_server_payload TEXT,
    selector_username TEXT,
    selector_status TEXT,
    selector_deadline REAL,
    selector_commit TEXT,
    selector_nonce TEXT,
    selector_client_nonce TEXT,
    selector_seed TEXT,
    selector_list_json TEXT,
    miner_list_json TEXT,
    selector_rewarded INTEGER DEFAULT 0,
    selector_attempts INTEGER DEFAULT 0,
    signed_by TEXT,
    signed_at REAL
);

CREATE TABLE IF NOT EXISTS pending_monetary_actions (
    action_id TEXT PRIMARY KEY,
    transfer_id TEXT NOT NULL,
    action_name TEXT NOT NULL,
    username TEXT NOT NULL,
    client_identifier TEXT,
    payload TEXT NOT NULL,
    response_event TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS transfer_signatures (
    signature_id TEXT PRIMARY KEY,
    transfer_id TEXT NOT NULL,
    miner TEXT NOT NULL,
    signature TEXT NOT NULL,
    contract_content BLOB NOT NULL,
    created_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS hps_voucher_offers (
    offer_id TEXT PRIMARY KEY,
    voucher_id TEXT NOT NULL,
    owner TEXT NOT NULL,
    payload TEXT NOT NULL,
    value INTEGER NOT NULL,
    reason TEXT NOT NULL,
    issued_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hps_transfer_sessions (
    session_id TEXT PRIMARY KEY,
    offer_id TEXT NOT NULL,
    voucher_id TEXT NOT NULL,
    payer TEXT NOT NULL,
    target TEXT NOT NULL,
    voucher_ids TEXT NOT NULL,
    amount INTEGER NOT NULL,
    total_value INTEGER NOT NULL,
    status TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS hps_issuer_invalidations (
    issuer TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    session_id TEXT,
    invalidated_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS hps_economy_stats (
    stat_key TEXT PRIMARY KEY,
    stat_value REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS fraud_restrictions (
    username TEXT NOT NULL,
    issuer TEXT NOT NULL,
    reason TEXT NOT NULL,
    restricted_at REAL NOT NULL,
    PRIMARY KEY (username, issuer)
);
