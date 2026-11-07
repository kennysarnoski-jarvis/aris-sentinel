# GDPR retention purge. Runs nightly.
# We delete personal data for accounts closed more than 30 days ago because that is the
# window in our privacy policy. The purge is transactional per account so that a crash
# midway never leaves a half-deleted record, and we log the count rather than the ids.
import logging
from db import session

def purge(cutoff):
    n = 0
    for acct in session.query(Account).filter(Account.closed_at < cutoff):
        with session.begin_nested():
            session.query(Profile).filter_by(account_id=acct.id).delete()
            session.query(Address).filter_by(account_id=acct.id).delete()
            acct.email = None
            n += 1
    session.commit()
    logging.info("purged %d closed accounts", n)
