"""zdc_cve.db.prune_superseded_payloads: the 0202 call is guarded, and never fatal."""

from zdc_cve import db


class Cur:
    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, *a):
        self.conn.sql.append(sql)
        if "prune_superseded_cve_payloads()" in sql and "to_regprocedure" not in sql and self.conn.boom:
            raise RuntimeError("lock timeout")
        self.last = sql

    def fetchone(self):
        if "to_regprocedure" in self.last:
            return (self.conn.exists,)
        return (3, 4_000_000)


class Conn:
    def __init__(self, exists=True, boom=False):
        self.exists, self.boom, self.sql, self.commits, self.rollbacks = exists, boom, [], 0, 0

    def cursor(self):
        return Cur(self)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


def test_prunes_and_commits_when_0202_is_applied():
    c = Conn()
    assert db.prune_superseded_payloads(c) == (3, 4_000_000) and c.commits == 1


def test_skips_where_0202_is_not_applied():
    c = Conn(exists=False)
    assert db.prune_superseded_payloads(c) is None and len(c.sql) == 1 and c.commits == 0


def test_a_failed_prune_rolls_back_and_does_not_raise():
    c = Conn(boom=True)
    assert db.prune_superseded_payloads(c) is None and c.rollbacks == 1 and c.commits == 0
