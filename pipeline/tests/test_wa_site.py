"""The atg.wa.gov breach list (R4): parser, id rules and the join. Synthetic pages only.

The page builder reproduces the Drupal view's markup as measured on 2026-10-21 (table cells keyed
by `headers`, dates as <time>, the notice PDF as the name's link, a ?page=N pager)."""

from __future__ import annotations

from datetime import date

from zdc_breach import sources_wa_site as w

_H = {"date_reported": "view-field-report-date-table-column",
      "organization": "view-field-full-title-table-column",
      "date_of_breach": "view-field-start-date-table-column",
      "wa_affected": "view-field-number-wa-affected-table-column",
      "information_compromised": "view-field-information-compromised-table-column"}


def _td(col, inner):
    return f'<td headers="{_H[col]}" class="views-field">{inner}          </td>'


def row(name, reported, start, n, info, pdf="A1"):
    t = lambda v: f'<time datetime="x">{v}</time>\n' if v else ""  # noqa: E731
    link = f'<a href="https://agportal-s3bucket.s3.amazonaws.com/databreach/Breach{pdf}.pdf">{name}</a>' if pdf else name
    return ("<tr>" + _td("date_reported", t(reported)) + _td("organization", link) + _td("date_of_breach", t(start))
            + _td("wa_affected", n) + _td("information_compromised", info) + "</tr>")


def page(rows, last=0):
    pager = "".join(f'<li><a href="?page={i}">{i + 1}</a></li>' for i in range(last + 1))
    head = "".join(f'<th id="{h}">x</th>' for h in _H.values())
    return (f'<html><body><a href="?page=99x">noise</a><table><thead><tr>{head}</tr></thead><tbody>'
            + "".join(rows) + f'</tbody></table><nav class="pager"><ul>{pager}</ul></nav></body></html>')


# ---- parser ------------------------------------------------------------------------------------
def test_parses_every_cell_and_the_notice_id():
    body = page([row("Zz Widgets, Inc.", "09/11/2026", "08/01/2026", "1,204",
                     "Name; Social Security Number; Financial &amp; Banking Information", pdf="A42768")], last=37)
    [n], bad, last = w.parse_page(body)
    assert bad == 0 and last == 37
    assert n.site_id == "site:A42768" and n.organization == "Zz Widgets, Inc."
    assert n.date_reported == date(2026, 9, 11) and n.date_of_breach == date(2026, 8, 1)
    assert n.wa_affected == 1204
    assert n.terms == ["Name", "Social Security Number", "Financial & Banking Information"]
    assert n.data_types == "Name, Social Security Number, Financial & Banking Information"
    assert n.record["information_compromised"].startswith("Name; Social")      # raw kept verbatim


def test_unknown_is_not_a_data_type():
    [a, b], _, _ = w.parse_page(page([row("Zz A", "01/02/2026", "", "Unknown", "Unknown", pdf="A1"),
                                      row("Zz B", "01/02/2026", "", "600", "Name; Unknown; Other", pdf="A2")]))
    assert a.terms == [] and a.data_types is None and a.wa_affected is None and a.date_of_breach is None
    assert b.terms == ["Name", "Other"]


def test_a_row_without_name_or_reported_date_is_malformed_not_guessed():
    ns, bad, _ = w.parse_page(page([row("", "01/02/2026", "", "600", "Name", pdf=None),
                                    row("Zz C", "", "", "600", "Name", pdf="A3"),
                                    row("Zz D", "13/45/2026", "", "600", "Name", pdf="A4"),
                                    row("Zz E", "01/02/2026", "", "600", "Name", pdf="A5")]))
    assert [n.organization for n in ns] == ["Zz E"] and bad == 3


def test_no_pdf_link_gets_a_stable_hashed_id():
    [a], _, _ = w.parse_page(page([row("Zz F", "01/02/2026", "", "600", "Name", pdf=None)]))
    [b], _, _ = w.parse_page(page([row("ZZ F", "01/02/2026", "", "999", "Name; Other", pdf=None)]))
    assert a.site_id.startswith("site:h") and a.site_id == b.site_id


def test_an_empty_or_reshaped_page_parses_to_nothing():
    assert w.parse_page("<html><body>maintenance</body></html>") == ([], 0, None)


def test_identical_rows_collapse_and_differing_rows_sharing_a_pdf_stay_apart():
    same = row("Zz G", "01/02/2026", "", "600", "Name", pdf="A7")
    ns, _, _ = w.parse_page(page([same, same, row("Zz H", "01/03/2026", "", "700", "Name", pdf="A7")]))
    out = w.dedupe_ids(ns)
    assert len(out) == 2 and len({n.site_id for n in out}) == 2
    assert all(n.site_id.startswith("site:A7#") for n in out)


def test_from_record_round_trips():
    [n], _, _ = w.parse_page(page([row("Zz I", "01/02/2026", "12/01/2025", "600", "Name; Unknown", pdf="A8")]))
    m = w.from_record(n.site_id, n.record)
    assert (m.organization, m.date_reported, m.date_of_breach, m.wa_affected, m.terms) == \
        (n.organization, n.date_reported, n.date_of_breach, n.wa_affected, n.terms)
    assert w.from_record("site:x", {"organization": "Zz"}) is None


# ---- join --------------------------------------------------------------------------------------
def _n(name, reported, sid):
    [x], _, _ = w.parse_page(page([row(name, reported, "", "600", "Name", pdf=sid)]))
    return x


D1, D2 = date(2026, 9, 11), date(2026, 9, 12)


def test_join_exact_normalised_name_and_same_date():
    res = w.join([_n("Zz Widgets, Inc.", "09/11/2026", "A1")], [("11", "ZZ WIDGETS INC", D1)])
    assert res["site:A1"] == ("11", w.JOINED)


def test_join_refuses_another_date_or_a_parenthetical():
    res = w.join([_n("Zz Widgets", "09/12/2026", "A1"), _n("Zz Clinic (Zz Vendor, LLC)", "09/11/2026", "A2")],
                 [("11", "Zz Widgets", D1), ("12", "Zz Clinic", D1)])
    assert res["site:A1"] == (None, w.NO_MATCH) and res["site:A2"] == (None, w.NO_MATCH)


def test_two_dataset_rows_with_one_key_join_nothing():
    res = w.join([_n("Zz Twin", "09/11/2026", "A1")], [("11", "Zz Twin", D1), ("12", "Zz Twin LLC", D1)])
    assert res["site:A1"] == (None, w.AMBIG_DATASET)


def test_two_site_notices_on_one_dataset_row_join_nothing():
    res = w.join([_n("Zz Twin", "09/11/2026", "A1"), _n("Zz Twin, Inc.", "09/11/2026", "A2"),
                  _n("Zz Solo", "09/11/2026", "A3")],
                 [("11", "Zz Twin", D1), ("13", "Zz Solo", D1), ("14", "Zz Solo", D2)])
    assert res["site:A1"] == (None, w.AMBIG_SITE) and res["site:A2"] == (None, w.AMBIG_SITE)
    assert res["site:A3"] == ("13", w.JOINED)


def test_a_name_that_normalises_to_nothing_never_joins():
    res = w.join([_n("Inc.", "09/11/2026", "A1")], [("11", "LLC", D1)])
    assert res["site:A1"] == (None, w.NO_MATCH)
