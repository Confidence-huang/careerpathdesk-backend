# PostgreSQL boundary

CareerPathDesk targets PostgreSQL 18. The only local development database name is `careerpathdesk_synthetic`; Compose project and volume names must also contain `careerpathdesk-synthetic`.

Numbered migrations live in `migrations/` and are applied only by the explicit Go migration command. The API process never creates, alters or repairs schema during startup. Foundation migration behavior is verified against the isolated PostgreSQL test database through transaction-backed tests.

Synthetic seed policy lives in `seeds/README.md`. No business rows are created by bootstrap or migration validation.

No v1 SQLite path, Linux restored candidate path or production connection string is valid input here.
