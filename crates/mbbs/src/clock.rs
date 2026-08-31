//! What time the host thinks it is.
//!
//! Three host routines read a clock -- `now`, `today` and `time` -- and until
//! this module they each read the wall independently. That is faithful to the
//! original, which read the DOS clock afresh every call, and it is why no test
//! could say what MajorMUD *built*: `srand(time(NULL))` six calls into
//! initialisation means every boot generated a different world, on the real
//! host as much as on this one.
//!
//! # A pinned clock is frozen, and that is a hazard worth naming
//!
//! [`Clock::system`] advances, because a board's clock does. [`Clock::pinned`]
//! returns the same instant forever. A future main loop that polled `now` until
//! it changed would spin under a pin -- nothing does that yet, and a pinned
//! clock that advanced by some invented amount per read would be a different
//! lie, not a smaller one.
//!
//! # Why the calendar is here rather than in `libc`
//!
//! `localtime_r` reads the `TZ` environment variable. A pinned test that
//! asserted a packed DOS date would then pass in one timezone and fail in
//! another, and setting `TZ` from a test is process-global and `unsafe` in Rust
//! 2024 with tests running in parallel.
//!
//! So a clock carries an **offset** -- seconds to add to the epoch to get what
//! a clock on the wall would read -- and the breakdown is computed here. One
//! code path, pinned or not. [`Clock::system`] fills the offset in once from
//! `tm_gmtoff`, at construction: a host that runs across a daylight-saving
//! boundary will not notice, which is what a DOS box did too.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

/// A broken-down local date and time, as a DOS-era clock would read it.
///
/// Fields are the ordinary human ones, not `struct tm`'s: `month` is 1..=12 and
/// `year` is the full year. `tm`'s zero-based month and 1900-based year are a
/// reliable source of off-by-one, and nothing here has to interoperate with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Civil {
    /// The full year, e.g. 2005.
    pub year: i32,
    /// 1..=12.
    pub month: u32,
    /// 1..=31.
    pub day: u32,
    /// 0..=23.
    pub hour: u32,
    /// 0..=59.
    pub minute: u32,
    /// 0..=59.
    pub second: u32,
}

impl Civil {
    /// The date, packed the way DOS packs it: years since 1980 in bits 15..9,
    /// month in 8..5, day in 4..0.
    ///
    /// What `today` returns, what `ncdate` and `ncedat` take apart, and the high
    /// half of what `getdtd` reports for a file. One function rather than three
    /// copies of the shift, because the three had no reason to disagree and
    /// every reason to be read together.
    ///
    /// # Errors
    ///
    /// If the year is outside 1980..=2107, which seven bits cannot hold. The
    /// old inline version clamped, which turned 1970 into 1980 -- a date that is
    /// wrong rather than absent.
    pub fn dos_date(&self) -> Result<u16, String> {
        if !(1980..=2107).contains(&self.year) {
            return Err(format!(
                "{} is not a year DOS can pack into seven bits",
                self.year
            ));
        }
        let year = (self.year - 1980) as u16;
        Ok((year << 9) | ((self.month as u16) << 5) | (self.day as u16))
    }

    /// The time, packed the way DOS packs it: hours in bits 15..11, minutes in
    /// 10..5, and **two-second units** in 4..0.
    ///
    /// Five bits will not hold 59, so the seconds are halved and an odd second
    /// cannot be represented at all -- which is why `nctime` doubles them back
    /// and never prints one. Cannot fail: every field of a [`Civil`] fits.
    pub fn dos_time(&self) -> u16 {
        ((self.hour as u16) << 11) | ((self.minute as u16) << 5) | (self.second as u16 / 2)
    }
}

/// The clock the host answers `now`, `today` and `time` from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clock {
    /// The instant in **milliseconds** since the epoch, or `None` to read the
    /// wall each time.
    ///
    /// Milliseconds rather than seconds only so that [`Clock::stepped`] can
    /// advance by less than a second; [`Clock::epoch`] still answers in whole
    /// seconds and every caller still sees the same instant it always did.
    at: Option<u64>,

    /// Milliseconds a read adds. `0` is a clock that does not move, which is
    /// both [`Clock::pinned`] and (meaninglessly, since it reads the wall)
    /// [`Clock::system`].
    step: u32,

    /// Seconds to add to the epoch to get what the wall clock reads. Positive
    /// east of Greenwich.
    offset: i32,
}

impl Clock {
    /// A clock that reads the wall, in the machine's own timezone.
    ///
    /// # Errors
    ///
    /// If the system clock is before 1970, or the C library will not break down
    /// the current time to tell us the offset.
    pub fn system() -> io::Result<Self> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| io::Error::other(e.to_string()))?
            .as_secs() as libc::time_t;

        // SAFETY: `localtime_r` fills the caller's `tm` and touches nothing
        // else. The zeroed struct is a valid `tm` for it to overwrite.
        let mut out: libc::tm = unsafe { std::mem::zeroed() };
        if unsafe { libc::localtime_r(&now, &mut out) }.is_null() {
            return Err(io::Error::other("the local timezone is unknown"));
        }
        Ok(Self {
            at: None,
            step: 0,
            offset: out.tm_gmtoff as i32,
        })
    }

    /// A clock frozen at `at`, seconds since the epoch, reading as UTC.
    ///
    /// Add [`Clock::with_offset`] for a clock frozen somewhere other than
    /// Greenwich.
    pub fn pinned(at: u32) -> Self {
        Self {
            at: Some(u64::from(at) * 1000),
            step: 0,
            offset: 0,
        }
    }

    /// A clock frozen at `at` that moves `step_millis` forward every time it is
    /// read.
    ///
    /// For [`crate::Host::cycle`], which cannot make an `rtkick` come due under
    /// a pin: `prcrtk` runs once per elapsed second and under `Clock::pinned` no
    /// second ever elapses. See `docs/plans/2026-08-08-polling-design.md`.
    ///
    /// The step is charged on every read, the host's own included, and
    /// [`crate::Host::clock_reads`] is what makes the size of that visible.
    pub fn stepped(at: u32, step_millis: u32) -> Self {
        Self {
            at: Some(u64::from(at) * 1000),
            step: step_millis,
            offset: 0,
        }
    }

    /// This clock, one step later. A no-op for a frozen clock, and for a system
    /// clock, which is already moving on its own.
    #[must_use]
    pub fn advanced(self) -> Self {
        match self.at {
            Some(at) => Self {
                at: Some(at.saturating_add(u64::from(self.step))),
                ..self
            },
            None => self,
        }
    }

    /// The same clock, `offset` seconds east of Greenwich.
    #[must_use]
    pub fn with_offset(self, offset: i32) -> Self {
        Self { offset, ..self }
    }

    /// Seconds since the epoch. **Not** shifted by the offset -- an instant is
    /// the same instant everywhere.
    ///
    /// # Errors
    ///
    /// If this is a system clock and the machine's is before 1970.
    pub fn epoch(&self) -> Result<u32, String> {
        match self.at {
            Some(at) => Ok((at / 1000) as u32),
            None => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as u32)
                .map_err(|e| e.to_string()),
        }
    }

    /// What a clock on the wall reads: the epoch shifted by the offset, broken
    /// down.
    ///
    /// # Errors
    ///
    /// If [`Clock::epoch`] cannot answer.
    pub fn civil(&self) -> Result<Civil, String> {
        Ok(Civil::from_local_epoch(
            i64::from(self.epoch()?) + i64::from(self.offset),
        ))
    }

    /// The local-time offset this clock applies, in seconds.
    ///
    /// For dating something that is not "now" -- a file's mtime, which
    /// `fnd1st` reports -- against the same wall clock everything else here
    /// uses. See [`Civil::from_local_epoch`].
    pub fn offset(&self) -> i32 {
        self.offset
    }

    /// Hundredths of the current second (`0..=99`), for DOS's `gettime`
    /// `ti_hund`.
    ///
    /// [`Clock::civil`] carries only whole seconds, so `gettime` used to
    /// report `ti_hund` as a flat `0` -- and a module that polls the clock to
    /// watch it tick *inside* one second (The Rose does this to pace its
    /// action/round timer) then saw it stand still, so the timer never
    /// advanced and a player could not act. A system clock reads the real
    /// sub-second nanos; a stepped clock reports whatever fraction its
    /// millisecond position has reached, so it visibly moves under a pin too.
    pub fn hundredths(&self) -> u8 {
        let millis_in_second = match self.at {
            Some(at) => (at % 1000) as u32,
            None => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.subsec_millis())
                .unwrap_or(0),
        };
        (millis_in_second / 10) as u8
    }

    /// Milliseconds since the epoch. For a free-running sub-second counter
    /// (`hrtval`) that must advance *within* one second, not jump once at each
    /// boundary.
    ///
    /// # Errors
    ///
    /// If this is a system clock and the machine's is before 1970.
    pub fn epoch_millis(&self) -> Result<u64, String> {
        match self.at {
            Some(at) => Ok(at),
            None => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .map_err(|e| e.to_string()),
        }
    }
}

impl Civil {
    /// Break a *local* epoch second down into a civil date and time.
    ///
    /// `local` is already offset -- seconds since 1970-01-01 in whatever zone
    /// the caller means -- so this does no zone arithmetic of its own.
    /// [`Clock::civil`] adds its own offset before calling; `fnd1st` adds
    /// [`Clock::offset`] to a file's mtime and calls the same function, so a
    /// file's reported date and `today`'s cannot disagree about what day it
    /// is.
    pub fn from_local_epoch(local: i64) -> Self {
        // Floor division, not truncation: an offset can carry a time back
        // before the epoch, where `-1 / 86400` truncates to 0 and would put
        // 23:00 on the 31st of December 1969 onto the 1st of January 1970.
        let days = local.div_euclid(86_400);
        let rest = local.rem_euclid(86_400);
        let (year, month, day) = civil_from_days(days);

        Self {
            year,
            month,
            day,
            hour: (rest / 3600) as u32,
            minute: ((rest / 60) % 60) as u32,
            second: (rest % 60) as u32,
        }
    }
}

/// The civil date `days` after 1970-01-01, proleptic Gregorian.
///
/// Howard Hinnant's `civil_from_days`, which is the standard formulation of
/// this and is what `<chrono>` uses. It shifts the year to start in March so
/// that the leap day lands at the end of it and no month-length table is
/// needed; `146097` is the days in a 400-year era and `36524` the days in a
/// century, which is where the "divisible by 100 but not 400" rule comes from
/// without being written down anywhere.
impl Civil {
    /// The inverse of [`Civil::from_local_epoch`]: this civil date and time
    /// as a *local* epoch second.
    ///
    /// The caller adds or subtracts [`Clock::offset`] as it needs; this does
    /// no zone arithmetic of its own, exactly as `from_local_epoch` does
    /// none.
    ///
    /// # Errors
    ///
    /// If the fields do not name a real instant -- month outside 1..=12, day
    /// outside the month, or an hour, minute or second out of range. A DOS
    /// `struct date`/`struct time` pair is four bytes of whatever the module
    /// put there, so this is reachable input rather than a formality.
    pub fn to_local_epoch(&self) -> Result<i64, String> {
        if !(1..=12).contains(&self.month) {
            return Err(format!("{} is not a month", self.month));
        }
        if self.hour > 23 || self.minute > 59 || self.second > 59 {
            return Err(format!(
                "{:02}:{:02}:{:02} is not a time of day",
                self.hour, self.minute, self.second
            ));
        }
        let days = days_from_civil(self.year, self.month, self.day)?;
        Ok(days * 86_400
            + i64::from(self.hour) * 3600
            + i64::from(self.minute) * 60
            + i64::from(self.second))
    }
}

/// Days since 1970-01-01 for a civil date -- Howard Hinnant's `days_from_civil`,
/// the exact inverse of [`civil_from_days`] below.
///
/// # Errors
///
/// If `day` is not a day of that month, which is what makes a `struct date`
/// full of arbitrary bytes a refusal rather than a date some months from
/// where the module meant.
fn days_from_civil(year: i32, month: u32, day: u32) -> Result<i64, String> {
    let last = last_day_of_month(year, month);
    if day < 1 || day > last {
        return Err(format!(
            "{day} is not a day of month {month} in {year}, which has {last}"
        ));
    }
    let y = i64::from(if month <= 2 { year - 1 } else { year });
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // 0..=399
    let m = i64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Ok(era * 146_097 + doe - 719_468)
}

/// How many days month `month` of `year` has.
fn last_day_of_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // 0..=146096
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // 0..=399
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // 0..=365
    let mp = (5 * doy + 2) / 153; // 0..=11, March is 0
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // 1..=31
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // 1..=12
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year as i32, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MajorMUD 1.11p's own build stamp, which is the instant this suite pins
    /// to: `Dec 30 2005 14:20:05`, as the audit line reports it.
    const BUILD: u32 = 1_135_952_405;

    #[test]
    fn a_pinned_clock_breaks_down_to_the_instant_it_was_pinned_to() {
        let c = Clock::pinned(BUILD).civil().expect("in range");
        assert_eq!(
            (c.year, c.month, c.day, c.hour, c.minute, c.second),
            (2005, 12, 30, 14, 20, 5)
        );
    }

    #[test]
    fn the_offset_moves_the_breakdown_and_not_the_epoch() {
        // What an offset is *for*: the epoch second is the same instant
        // everywhere, and the offset is only how a clock on the wall reads it.
        let utc = Clock::pinned(BUILD);
        let east = utc.with_offset(5 * 3600);

        assert_eq!(utc.epoch().expect("now"), east.epoch().expect("now"));
        assert_eq!(east.civil().expect("in range").hour, 19);
        assert_eq!(east.civil().expect("in range").day, 30);
    }

    #[test]
    fn an_offset_can_carry_the_breakdown_into_the_next_day() {
        // 14:20 plus ten hours is the following morning, and the month and the
        // year have to come with it. A conversion that only adjusted the hour
        // would pass every assertion above.
        let c = Clock::pinned(BUILD).with_offset(10 * 3600);
        let c = c.civil().expect("in range");
        assert_eq!((c.year, c.month, c.day, c.hour), (2005, 12, 31, 0));
    }

    #[test]
    fn a_negative_offset_can_carry_it_back() {
        let c = Clock::pinned(BUILD).with_offset(-15 * 3600);
        let c = c.civil().expect("in range");
        assert_eq!((c.year, c.month, c.day, c.hour), (2005, 12, 29, 23));
    }

    #[test]
    fn the_epoch_itself_is_the_first_of_january_1970() {
        let c = Clock::pinned(0).civil().expect("in range");
        assert_eq!(
            (c.year, c.month, c.day, c.hour, c.minute, c.second),
            (1970, 1, 1, 0, 0, 0)
        );
    }

    #[test]
    fn a_leap_day_is_a_day() {
        // 2000 is a leap year (divisible by 400), 1900 was not (divisible by
        // 100). The civil conversion has to know the difference, and a run of
        // days that never crosses one would not find out.
        let leap = Clock::pinned(951_782_400).civil().expect("in range");
        assert_eq!((leap.year, leap.month, leap.day), (2000, 2, 29));

        let after = Clock::pinned(951_782_400 + 86_400)
            .civil()
            .expect("in range");
        assert_eq!((after.year, after.month, after.day), (2000, 3, 1));
    }

    #[test]
    fn a_pinned_clock_does_not_advance() {
        // The whole point, and the hazard: a main loop that waited for `now` to
        // change would wait forever. Nothing does that yet.
        let c = Clock::pinned(BUILD);
        assert_eq!(c.epoch().expect("now"), c.epoch().expect("now"));
        assert_eq!(c.epoch().expect("now"), BUILD);
    }

    #[test]
    fn a_system_clock_reads_the_wall_and_advances() {
        let c = Clock::system().expect("a system clock");
        let seconds = c.epoch().expect("now");
        // Later than the day this was written, and not obviously wrong.
        assert!(seconds > 1_750_000_000, "{seconds}");
        assert!(c.civil().expect("in range").year >= 2025);
    }

    #[test]
    fn a_stepped_clock_advances_and_a_pinned_one_does_not() {
        let pinned = Clock::pinned(1_135_952_405);
        assert_eq!(pinned.advanced().epoch(), Ok(1_135_952_405), "frozen stays frozen");

        // 50 ms a read: twenty reads to the second, and nineteen that change
        // nothing an `epoch()` caller can see.
        let mut c = Clock::stepped(1_135_952_405, 50);
        for _ in 0..19 {
            c = c.advanced();
            assert_eq!(c.epoch(), Ok(1_135_952_405), "still inside the first second");
        }
        c = c.advanced();
        assert_eq!(c.epoch(), Ok(1_135_952_406), "the twentieth read crosses it");
    }

    #[test]
    fn a_stepped_clock_still_breaks_down_to_a_civil_time() {
        let c = Clock::stepped(1_135_952_405, 1000).advanced();
        let civil = c.civil().expect("broken down");
        assert_eq!(civil.second, 6, "1_135_952_405 is :05, one second on is :06");
    }

    #[test]
    fn hundredths_report_the_sub_second_position() {
        // A whole-second pin has nothing below the second: flat zero, which is
        // what `gettime`'s own test still reads.
        assert_eq!(Clock::pinned(1_135_952_405).hundredths(), 0);
        // A stepped clock's millisecond position moves, so the clock visibly
        // ticks within one second -- the fix The Rose needed from `gettime`.
        let c = Clock::stepped(1_135_952_405, 250); // quarter-second a read
        assert_eq!(c.hundredths(), 0);
        let c = c.advanced();
        assert_eq!(c.hundredths(), 25, "250 ms in is 25 hundredths");
        let c = c.advanced();
        assert_eq!(c.hundredths(), 50);
    }

    #[test]
    fn epoch_millis_keeps_the_sub_second_epoch_drops() {
        // `hrtval` derives its smooth 65,536/second advance from milliseconds,
        // so `epoch_millis` must carry what `epoch`'s whole seconds throw away.
        let c = Clock::stepped(100, 250).advanced(); // a quarter-second in
        assert_eq!(c.epoch_millis().unwrap(), 100_250);
        assert_eq!(c.epoch().unwrap(), 100, "epoch is whole seconds only");
    }
}
