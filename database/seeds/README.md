# Synthetic seed boundary

Only deterministic, visibly synthetic CareerPathDesk fixtures may live here. The seed command rejects non-synthetic runtime modes and never reads v1 SQLite, restored candidates, exports, contact lists, or external data sources.

`synthetic.sql` restores one fixed fixture set: one owner, two staff profiles/accounts, four students without contact details, and four active primary assignments. It creates no coaching tasks or stage-change history. Repeating the command restores the same identities and fixed values. The public synthetic-only initial password is encoded through a deterministic Argon2id hash and every seeded account still requires first-password change; neither the password nor hash is printed by the command.
