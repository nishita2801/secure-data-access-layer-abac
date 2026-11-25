import json
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

from secure_data_access_layer.data_access import SecureDataAccess
from secure_data_access_layer.models import (
    AccessRequest,
    Action,
    Classification,
    Environment,
    Resource,
    Subject,
)


st.set_page_config(
    page_title="Secure Data Access",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .stApp { background: #f4f7fb; }
    .block-container { max-width: 1420px; padding-top: 2rem; padding-bottom: 3rem; }
    [data-testid="stSidebar"] { background: #101b33; }
    [data-testid="stSidebar"] * { color: #edf3ff; }
    .hero {
        padding: 1.8rem 2rem; border-radius: 20px; margin-bottom: 1.2rem;
        background: linear-gradient(120deg, #14264a 0%, #234b80 62%, #287d8e 100%);
        color: #f8fbff; box-shadow: 0 12px 32px rgba(24, 53, 91, .16);
    }
    .hero .eyebrow { color: #b8dcf2; font-size: .78rem; font-weight: 700;
        letter-spacing: .14em; text-transform: uppercase; }
    .hero h1 { color: #fff; margin: .45rem 0 .3rem; font-size: 2.2rem; }
    .hero p { color: #e1edf8; margin: 0; font-size: 1.05rem; }
    div[data-testid="stMetric"] {
        background: #fff; border: 1px solid #e6ebf2; border-radius: 14px;
        padding: 1rem 1.1rem; box-shadow: 0 3px 12px rgba(25, 45, 75, .04);
    }
    div[data-testid="stForm"] {
        background: #fff; border: 1px solid #e6ebf2; border-radius: 16px;
        padding: 1.2rem; box-shadow: 0 4px 16px rgba(25, 45, 75, .04);
    }
    .section-note { color: #64748b; font-size: .94rem; margin-top: -.45rem; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="hero">
      <div class="eyebrow">Access governance · interactive demo</div>
      <h1>Secure Data Access</h1>
      <p>Explore how identity, tenant, data sensitivity, action, and MFA shape an access decision.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.markdown("## 🔐 ABAC Console")
    st.caption("Policy decision point · tenant-aware data layer · audit trail")
    st.divider()
    st.markdown("### Policy at a glance")
    st.markdown(
        """
        - Tenant must match the requested data.
        - Clearance must meet data classification.
        - Confidential and Restricted data require MFA.
        - Only authorized reads return sales rows.
        - The displayed demo identity does not grant permissions.
        """
    )
    st.divider()
    st.caption("Demo data is stored locally in SQLite.")

st.subheader("Request access")
st.markdown(
    '<p class="section-note">Choose a quick scenario or customize each attribute below.</p>',
    unsafe_allow_html=True,
)


def apply_scenario(role, subject_tenant, resource_tenant, clearance, classification, mfa):
    st.session_state["role"] = role
    st.session_state["subject_tenant"] = subject_tenant
    st.session_state["resource_tenant"] = resource_tenant
    st.session_state["user_clearance"] = clearance
    st.session_state["data_classification"] = classification
    st.session_state["mfa_verified"] = mfa
    st.session_state.pop("last_decision", None)


scenario_columns = st.columns(3)
with scenario_columns[0]:
    if st.button("✅  Same-tenant read", use_container_width=True):
        apply_scenario(
            "analyst",
            "tenant-a",
            "tenant-a",
            Classification.INTERNAL,
            Classification.INTERNAL,
            True,
        )
        st.rerun()

with scenario_columns[1]:
    if st.button("↔️  Cross-tenant request", use_container_width=True):
        apply_scenario(
            "analyst",
            "tenant-a",
            "tenant-b",
            Classification.INTERNAL,
            Classification.INTERNAL,
            True,
        )
        st.rerun()

with scenario_columns[2]:
    if st.button("🛡️  Missing MFA", use_container_width=True):
        apply_scenario(
            "analyst",
            "tenant-a",
            "tenant-a",
            Classification.RESTRICTED,
            Classification.CONFIDENTIAL,
            False,
        )
        st.rerun()


with st.form("access_request_form"):
    identity_column, resource_column = st.columns(2, gap="large")

    with identity_column:
        st.markdown("#### 1 · Who is requesting?")
        role = st.selectbox(
            "Demo identity (display only)",
            ["analyst", "engineer", "admin"],
            key="role",
        )
        subject_tenant = st.selectbox(
            "User's tenant",
            ["tenant-a", "tenant-b"],
            key="subject_tenant",
        )
        clearance = st.selectbox(
            "User clearance",
            list(Classification),
            format_func=lambda value: value.name.title(),
            key="user_clearance",
        )

    with resource_column:
        st.markdown("#### 2 · What is being requested?")
        resource_tenant = st.selectbox(
            "Data tenant",
            ["tenant-a", "tenant-b"],
            key="resource_tenant",
        )
        action = st.selectbox(
            "Requested action",
            list(Action),
            format_func=lambda value: value.value.title(),
            key="requested_action",
        )
        classification = st.selectbox(
            "Data classification",
            list(Classification),
            format_func=lambda value: value.name.title(),
            key="data_classification",
        )

    mfa_verified = st.checkbox("MFA verified", value=True, key="mfa_verified")
    submitted = st.form_submit_button(
        "Check access",
        type="primary",
        use_container_width=True,
    )


if submitted:
    request = AccessRequest(
        subject=Subject(
            user_id=f"{role}-001",
            role=role,
            tenant_id=subject_tenant,
            clearance=clearance,
        ),
        resource=Resource(
            resource_id="sales",
            tenant_id=resource_tenant,
            classification=classification,
        ),
        action=action,
        environment=Environment(
            requested_at=datetime.now(timezone.utc),
            mfa_verified=mfa_verified,
        ),
    )

    try:
        records = SecureDataAccess().get_sales(request)
        st.session_state["last_decision"] = {
            "allowed": True,
            "reason": "Access granted.",
            "records": records,
            "role": role,
            "subject_tenant": subject_tenant,
            "resource_tenant": resource_tenant,
            "action": action.value,
        }
    except PermissionError as error:
        st.session_state["last_decision"] = {
            "allowed": False,
            "reason": str(error),
            "records": [],
            "role": role,
            "subject_tenant": subject_tenant,
            "resource_tenant": resource_tenant,
            "action": action.value,
        }


st.divider()
st.subheader("Decision")

decision = st.session_state.get("last_decision")
if decision is None:
    st.info("Submit an access request to see the policy decision and matching data.")
else:
    outcome = "ALLOW" if decision["allowed"] else "DENY"
    metric_columns = st.columns(3)
    metric_columns[0].metric("Policy decision", outcome)
    metric_columns[1].metric("Demo identity", decision["role"].title())
    metric_columns[2].metric("Requested action", decision["action"].title())

    if decision["allowed"]:
        st.success(decision["reason"])
        st.dataframe(
            decision["records"],
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.error(decision["reason"])


audit_tab, policy_tab = st.tabs(["🧾  Audit trail", "📘  Policy reference"])

with audit_tab:
    st.markdown("#### Recent access decisions")
    log_path = Path(__file__).resolve().parents[2] / "logs" / "access.log"
    entries = []

    if log_path.exists():
        for line in log_path.read_text(encoding="utf-8").splitlines():
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    if entries:
        filter_columns = st.columns([1, 3])
        decision_filter = filter_columns[0].selectbox(
            "Filter decisions",
            ["All", "ALLOW", "DENY"],
        )
        visible_entries = list(reversed(entries[-100:]))

        if decision_filter != "All":
            visible_entries = [
                entry
                for entry in visible_entries
                if entry.get("decision") == decision_filter
            ]

        st.caption(f"Showing {len(visible_entries)} of {len(entries)} recorded events.")
        st.dataframe(
            visible_entries,
            use_container_width=True,
            hide_index=True,
        )
    else:
        st.info("No access attempts have been logged yet.")


with policy_tab:
    st.markdown("#### Decision rules")
    st.dataframe(
        [
            {
                "Check": "Tenant isolation",
                "Rule": "User tenant must match data tenant",
            },
            {
                "Check": "Clearance",
                "Rule": "User clearance must meet or exceed classification",
            },
            {
                "Check": "MFA",
                "Rule": "Required for Confidential and Restricted data",
            },
            {
                "Check": "ABAC attributes",
                "Rule": (
                    "Decisions use tenant, clearance, classification, action, and MFA; "
                    "the displayed demo identity does not grant permissions"
                ),
            },
            {
                "Check": "Data service",
                "Rule": "This demo currently returns authorized sales reads only",
            },
        ],
        use_container_width=True,
        hide_index=True,
    )