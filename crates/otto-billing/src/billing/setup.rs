//! Starting to put a card on file.

use otto_tenant::audit::Entry;
use otto_tenant::ids::OrgId;
use otto_tenant::Db;
use serde_json::json;

use super::{idem, read_row, record_customer, Error, OrgLease, Result, LEASE_WAIT};
use crate::stripe::{
    Client, CreateCustomer, CreateSetupCheckoutSession, IdempotencyKey, SetupPaymentMethods,
};

/// What [`start_setup`] needs to know about the org and its owner.
#[derive(Debug, Clone)]
pub struct SetupParams<'a> {
    pub org: OrgId,
    /// The Stripe customer's name.
    pub org_name: &'a str,
    /// The requesting owner's email, for the Stripe customer (receipts and
    /// invoices go there). `None` for an account with no address yet.
    pub owner_email: Option<&'a str>,
    /// Where Checkout returns the owner on success and on cancel.
    pub success_url: String,
    pub cancel_url: String,
}

/// Start putting a card on file: find or create the org's Stripe customer,
/// then a Checkout session in setup mode for it, and return the session's
/// URL to send the owner to.
///
/// **Cards only** (`payment_method_types[]=card`). Bank debits confirm
/// asynchronously, so their setup could complete in Checkout and never
/// produce a card on file here; a card confirms before Checkout returns.
///
/// `audit` is the `billing.setup.started` entry with its actor and request
/// details; it is written, with the session id, once the session exists.
///
/// [`super::Error::Busy`] when another billing change for the org does not
/// finish within [`LEASE_WAIT`].
pub async fn start_setup(
    db: &Db,
    client: &Client,
    params: SetupParams<'_>,
    audit: Entry,
) -> Result<String> {
    let lease = OrgLease::acquire(db, params.org, LEASE_WAIT).await?;
    let result = setup(db, client, &lease, params, audit).await;
    lease.release(db).await;
    result
}

/// The work of [`start_setup`], under `lease`. Every write after a Stripe
/// call goes through [`OrgLease::begin`], so a worker that lost the lease
/// writes nothing.
async fn setup(
    db: &Db,
    client: &Client,
    lease: &OrgLease,
    params: SetupParams<'_>,
    audit: Entry,
) -> Result<String> {
    let org = params.org;
    let existing = read_row(db, org)
        .await?
        .and_then(|row| row.stripe_customer_id);
    let customer = match existing {
        Some(customer) => customer,
        None => {
            lease.renew(db).await?;
            let customer = find_or_create_customer(client, &params).await?;
            // Recorded at once, each in its own short transaction: the map
            // first (unpinned; true whoever holds the lease, as the customer
            // is tagged with this org), then the org's row, under the lease.
            record_customer(db, &customer, org).await?;
            let mut tx = lease.begin(db).await?;
            sqlx::query(
                "UPDATE subscriptions SET stripe_customer_id = $2, updated_at = now() \
                 WHERE org_id = $1",
            )
            .bind(org)
            .bind(&customer)
            .execute(tx.conn())
            .await?;
            tx.commit().await?;
            customer
        }
    };

    lease.renew(db).await?;
    // A fresh session per request: nothing retries this call, and a session
    // replayed from an earlier click may already be completed or expired.
    let session = client
        .create_setup_checkout_session(
            &CreateSetupCheckoutSession {
                customer: customer.clone(),
                payment_methods: SetupPaymentMethods::Types(vec!["card".to_owned()]),
                success_url: params.success_url,
                cancel_url: params.cancel_url,
                org_id: org.to_string(),
            },
            &IdempotencyKey::random(),
        )
        .await?;
    let url = session
        .url
        .ok_or_else(|| Error::Unexpected("the Checkout session has no url".into()))?;

    let mut tx = lease.begin(db).await?;
    tx.audit(
        audit
            .target("org", org.to_string())
            .detail(json!({ "checkoutSessionId": session.id })),
    )
    .await?;
    tx.commit().await?;
    Ok(url)
}

/// The org's Stripe customer: one already tagged `metadata[org_id]` (left by
/// an earlier attempt whose write did not happen), or a new one.
async fn find_or_create_customer(client: &Client, params: &SetupParams<'_>) -> Result<String> {
    let org = params.org.to_string();
    let found = client
        .search_customers_by_metadata("org_id", &org)
        .await?
        .data
        .into_iter()
        .find(|c| c.metadata.get("org_id") == Some(&org));
    if let Some(customer) = found {
        tracing::info!(org = %params.org, customer = %customer.id, "adopted an existing Stripe customer");
        return Ok(customer.id);
    }
    let create = CreateCustomer {
        email: params.owner_email.map(str::to_owned),
        name: Some(params.org_name.to_owned()),
        metadata: [("org_id".to_owned(), org)].into(),
    };
    let created = client
        .create_customer(&create, &idem("customer", &create)?)
        .await?;
    Ok(created.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::billing::mock::MockStripe;
    use std::time::Duration;

    #[sqlx::test(migrator = "otto_tenant::db::MIGRATOR")]
    async fn setup_with_a_lost_lease_writes_and_sends_nothing(pool: sqlx::PgPool) {
        let db = Db::from_pool(pool.clone());
        let mock = MockStripe::start().await;
        let org: uuid::Uuid = sqlx::query_scalar(
            "INSERT INTO orgs (slug, name) VALUES ('acme', 'Acme') RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let org = OrgId::from(org);
        let lease = OrgLease::acquire(&db, org, Duration::from_secs(1))
            .await
            .unwrap();
        // Another worker takes the org (the lease expired under a slow call).
        sqlx::query("UPDATE subscriptions SET lease_token = gen_random_uuid()")
            .execute(&pool)
            .await
            .unwrap();
        let params = SetupParams {
            org,
            org_name: "acme",
            owner_email: None,
            success_url: "https://otto.test/ok".into(),
            cancel_url: "https://otto.test/no".into(),
        };
        let err = setup(
            &db,
            &mock.client(),
            &lease,
            params,
            Entry::new("billing.setup.started"),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Error::LeaseLost(o) if o == org), "{err}");
        assert!(
            mock.posts().is_empty(),
            "a worker without the lease called Stripe"
        );
        let (customer, audits): (Option<String>, i64) = sqlx::query_as(
            "SELECT s.stripe_customer_id, \
                    (SELECT count(*) FROM audit_events WHERE org_id = $1) \
             FROM subscriptions s WHERE s.org_id = $1",
        )
        .bind(org)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!((customer, audits), (None, 0));
    }
}
