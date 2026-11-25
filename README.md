
# Secure Data Access Layer with ABAC

A Python demonstration of Attribute-Based Access Control (ABAC) for tenant-aware access to sales data. Each request is evaluated using subject, resource, action, and environment attributes. Access decisions are enforced before sales data is returned and recorded in an audit log.

## Project components

- `src/secure_data_access_layer/models.py` defines the subject, resource, action, environment, and access-request models.
- `src/secure_data_access_layer/policy.py` contains the Policy Decision Point (PDP), which evaluates access requests using tenant, clearance, resource classification, action, and MFA attributes.
- `src/secure_data_access_layer/data_access.py` initializes the sample SQLite database and enforces authorization and tenant filtering before returning sales rows.
- `src/secure_data_access_layer/audit.py` writes JSON-formatted access decisions to the audit log.
- `src/secure_data_access_layer/app.py` provides a Streamlit dashboard for submitting access requests and viewing recent audit events.
- `data/` stores the local SQLite database; `logs/` stores the local audit log.

## Architecture

```mermaid
flowchart LR
    U[User / Streamlit dashboard] --> R[Access request<br/>subject, resource, action, environment]
    R --> D{Policy Decision Point}
    D -->|Deny| A[Audit log: DENY]
    D -->|Allow| L[Secure data access layer]
    L -->|Tenant-filtered query| DB[(SQLite sales data)]
    L --> A2[Audit log: ALLOW]
    DB --> O[Authorized rows returned to dashboard]