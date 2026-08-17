//! The three time formats a Win32 DOS-era program moves between, and the
//! conversions among them.
//!
//! ```text
//! FILETIME    64-bit count of 100-nanosecond ticks since 1601-01-01 UTC
//! SYSTEMTIME  eight WORDs: year, month, weekday, day, hour, minute, sec, ms
//! DOS date/time  two packed WORDs, FAT-style, 1980-relative, 2-second seconds
//! ```
//!
//! They are gathered here rather than spread across the modules that use them
//! because the arithmetic is shared: `stream`'s directory entries and
//! `kernel32`'s `FileTimeToDosDateTime` are the same conversion reached from
//! two directions, and two copies would be two chances to get the epoch offset
//! wrong in only one of them.
//!
//! **The epoch gap is 11,644,473,600 seconds** -- 1601-01-01 to 1970-01-01,
//! 369 years including 89 leap days. It is written once, here.

/// Seconds between 1601-01-01 and 1970-01-01.
pub const EPOCH_GAP: i64 = 11_644_473_600;

/// 100-nanosecond ticks per second.
pub const TICKS_PER_SECOND: i64 = 10_000_000;

/// Days from 1970-01-01 to a civil date, by Howard Hinnant's `days_from_civil`.
///
/// Exact across the whole proleptic Gregorian calendar and free of the
/// leap-year special cases a hand-rolled version gets wrong in 2100 -- which is
/// inside the range a file timestamp can reach.
pub fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = year - i64::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// A FAT date/time pair to seconds since the Unix epoch.
///
/// ```text
/// date: yyyyyyym mmmddddd   year is 1980-relative, month 1-12, day 1-31
/// time: hhhhhmmm mmmsssss   seconds are in *two-second* units
/// ```
///
/// The two-second granularity is FAT's own: five bits hold half the value. A
/// conversion that forgot the doubling would put every timestamp in the first
/// 32 seconds of its minute.
pub fn unix_from_dos(date: u16, time: u16) -> i64 {
    let year = 1980 + i64::from(date >> 9);
    let month = i64::from((date >> 5) & 0x0f).clamp(1, 12);
    let day = i64::from(date & 0x1f).clamp(1, 31);
    let hour = i64::from(time >> 11);
    let minute = i64::from((time >> 5) & 0x3f);
    let second = i64::from(time & 0x1f) * 2;
    days_from_civil(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second
}

/// Seconds since the Unix epoch to a FAT date/time pair.
///
/// Dates before 1980 clamp to 1980-01-01, which is what FAT does: the format
/// cannot represent them, and wrapping would put a 1979 file in 2107.
pub fn dos_from_unix(secs: i64) -> (u16, u16) {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let t = secs as libc::time_t;
    // SAFETY: `t` is a live `time_t` and `tm` a live owned `struct tm`; the `_r`
    // form writes only through the pointer given and keeps no shared state.
    if unsafe { libc::gmtime_r(&t, &mut tm) }.is_null() {
        return (0x0021, 0);
    }
    let year = tm.tm_year + 1900;
    if year < 1980 {
        // 1980-01-01 00:00:00: month 1, day 1 packs as 0x0021.
        return (0x0021, 0);
    }
    let date = u16::try_from(((year - 1980) << 9) | ((tm.tm_mon + 1) << 5) | tm.tm_mday)
        .unwrap_or(0x0021);
    let time = u16::try_from((tm.tm_hour << 11) | (tm.tm_min << 5) | (tm.tm_sec / 2)).unwrap_or(0);
    (date, time)
}

/// Seconds since the Unix epoch to `FILETIME` ticks.
pub fn ticks_from_unix(secs: i64) -> u64 {
    u64::try_from((secs + EPOCH_GAP).max(0)).unwrap_or(0) * u64::try_from(TICKS_PER_SECOND).expect("positive")
}

/// `FILETIME` ticks to seconds since the Unix epoch.
pub fn unix_from_ticks(ticks: u64) -> i64 {
    i64::try_from(ticks / u64::try_from(TICKS_PER_SECOND).expect("positive")).unwrap_or(0) - EPOCH_GAP
}

/// The local timezone's offset from UTC, in seconds, at `secs`.
///
/// Read from the host's own timezone database rather than assumed, so daylight
/// saving is handled for the date in question rather than for today. A fixed
/// offset would be wrong for half the year in most of the world.
pub fn utc_offset(secs: i64) -> i64 {
    let t = secs as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: as `dos_from_unix` above.
    if unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
        return 0;
    }
    tm.tm_gmtoff
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The epoch gap, checked rather than trusted: 1601-01-01 is exactly this
    /// far before 1970-01-01.
    #[test]
    fn the_epoch_gap_is_the_distance_between_1601_and_1970() {
        assert_eq!(days_from_civil(1601, 1, 1) * 86_400, -EPOCH_GAP);
        assert_eq!(days_from_civil(1970, 1, 1), 0);
    }

    /// A known date, in and out. 1980-01-01 is FAT's own zero.
    #[test]
    fn the_dos_epoch_round_trips() {
        let (date, time) = (0x0021u16, 0u16);
        let secs = unix_from_dos(date, time);
        assert_eq!(secs, days_from_civil(1980, 1, 1) * 86_400);
        assert_eq!(dos_from_unix(secs), (date, time));
    }

    /// Seconds are stored halved. A conversion that forgets puts every
    /// timestamp in the first 32 seconds of its minute.
    #[test]
    fn dos_seconds_are_two_second_units() {
        // 1990-06-15 12:34:58
        let secs = days_from_civil(1990, 6, 15) * 86_400 + 12 * 3600 + 34 * 60 + 58;
        let (date, time) = dos_from_unix(secs);
        assert_eq!(time & 0x1f, 29, "58 seconds is stored as 29");
        assert_eq!(unix_from_dos(date, time), secs, "and reads back as 58");
    }

    /// A date FAT cannot hold clamps rather than wrapping into the far future.
    #[test]
    fn a_date_before_1980_clamps_instead_of_wrapping() {
        let secs = days_from_civil(1970, 1, 1) * 86_400;
        assert_eq!(dos_from_unix(secs), (0x0021, 0));
    }

    /// `FILETIME` ticks round-trip through Unix seconds.
    #[test]
    fn filetime_ticks_round_trip() {
        for secs in [0i64, 1, 1_000_000_000, 1_700_000_000] {
            assert_eq!(unix_from_ticks(ticks_from_unix(secs)), secs);
        }
        // 1601-01-01 itself is zero ticks.
        assert_eq!(ticks_from_unix(-EPOCH_GAP), 0);
    }

    /// The leap-year rule that a hand-rolled conversion gets wrong: 2000 is a
    /// leap year and 1900 and 2100 are not.
    #[test]
    fn the_gregorian_century_rule_is_respected() {
        let days_in_feb = |y: i64| days_from_civil(y, 3, 1) - days_from_civil(y, 2, 1);
        assert_eq!(days_in_feb(2000), 29, "divisible by 400");
        assert_eq!(days_in_feb(1900), 28, "divisible by 100 but not 400");
        assert_eq!(days_in_feb(2100), 28);
        assert_eq!(days_in_feb(2024), 29, "the ordinary rule");
    }
}
