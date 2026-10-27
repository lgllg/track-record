"""NYSE full-day market holidays, computed from the exchange's rules (no yearly list to maintain).

Rules (NYSE Rule 7.2): a holiday on Saturday is observed the Friday before, on Sunday the Monday
after; exception: New Year's Day on a Saturday is not observed. Unscheduled closures (e.g. a
national day of mourning) are announced separately and recorded as such in the ledger.
"""
import datetime as dt
from functools import lru_cache


def _nth_weekday(y, month, weekday, n):
    d = dt.date(y, month, 1)
    d += dt.timedelta(days=(weekday - d.weekday()) % 7)
    return d + dt.timedelta(weeks=n - 1)


def _last_weekday(y, month, weekday):
    d = dt.date(y, month + 1, 1) - dt.timedelta(days=1)
    return d - dt.timedelta(days=(d.weekday() - weekday) % 7)


def _easter(y):
    a, b, c = y % 19, y // 100, y % 100
    d, e = divmod(b, 4)
    g = (8 * b + 13) // 25
    h = (19 * a + b - d - g + 15) % 30
    i, k = divmod(c, 4)
    l = (32 + 2 * e + 2 * i - h - k) % 7
    m = (a + 11 * h + 22 * l) // 451
    month, day = divmod(h + l - 7 * m + 114, 31)
    return dt.date(y, month, day + 1)


def _observed(d):
    if d.weekday() == 5:
        return d - dt.timedelta(days=1)
    if d.weekday() == 6:
        return d + dt.timedelta(days=1)
    return d


@lru_cache(maxsize=None)
def holidays(y: int) -> dict:
    h = {}
    ny = dt.date(y, 1, 1)
    if ny.weekday() != 5:
        h[_observed(ny)] = "New Year's Day"
    h[_nth_weekday(y, 1, 0, 3)] = "Martin Luther King Jr. Day"
    h[_nth_weekday(y, 2, 0, 3)] = "Washington's Birthday"
    h[_easter(y) - dt.timedelta(days=2)] = "Good Friday"
    h[_last_weekday(y, 5, 0)] = "Memorial Day"
    if y >= 2022:
        h[_observed(dt.date(y, 6, 19))] = "Juneteenth"
    h[_observed(dt.date(y, 7, 4))] = "Independence Day"
    h[_nth_weekday(y, 9, 0, 1)] = "Labor Day"
    h[_nth_weekday(y, 11, 3, 4)] = "Thanksgiving Day"
    h[_observed(dt.date(y, 12, 25))] = "Christmas Day"
    return h


def holiday_name(d: dt.date) -> str | None:
    return holidays(d.year).get(d)


def is_trading_day(d: dt.date) -> bool:
    return d.weekday() < 5 and d not in holidays(d.year)
