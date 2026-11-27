// SPDX-License-Identifier: Apache-2.0
//! The agent's log lines on stdout (tracing-subscriber's default writer). When stdout is the journal, every line starts with the syslog priority of its level
//! (`<N>`, sd-daemon(3); journald reads it with `SyslogLevelPrefix=yes`, the default) and is stored with that priority:
//! the audit lines (`WARN … denied`, `WARN call … DESTRUCTIVE`, rollback, reboot, raise) are priority 4, so
//! `journalctl -p 4` and `foilctl journal --priority 4` show them. Without the prefix journald stored every line at
//! priority 6 and a priority filter hid them. stdout is the journal when `JOURNAL_STREAM` (`<dev>:<inode>`, set by
//! systemd for a service whose output goes to the journal) names stdout's own device and inode (systemd.exec(5)): a
//! process started from a terminal inside such a service, or with stdout redirected, writes no prefix.
use std::fmt;
use std::os::unix::fs::MetadataExt;
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::format::{FormatEvent, FormatFields, Writer};
use tracing_subscriber::fmt::FmtContext;
use tracing_subscriber::registry::LookupSpan;

/// The syslog priority of a level: ERROR 3 (err), WARN 4 (warning), INFO 6 (info), DEBUG and TRACE 7 (debug).
pub fn priority(level: &Level) -> u8 {
    match *level {
        Level::ERROR => 3,
        Level::WARN => 4,
        Level::INFO => 6,
        _ => 7,
    }
}

/// `JOURNAL_STREAM` (`<dev>:<inode>`, decimal) names this device and inode.
pub fn journal_stream_is(value: &str, dev: u64, ino: u64) -> bool {
    match value.split_once(':') {
        Some((d, i)) => d.parse::<u64>().ok() == Some(dev) && i.parse::<u64>().ok() == Some(ino),
        None => false,
    }
}

/// stdout of this process is the journal stream systemd connected (systemd.exec(5), `$JOURNAL_STREAM`).
pub fn stdout_is_journal() -> bool {
    let Some(v) = std::env::var_os("JOURNAL_STREAM") else { return false };
    let Ok(m) = std::fs::metadata("/proc/self/fd/1") else { return false };
    v.to_str().is_some_and(|v| journal_stream_is(v, MetadataExt::dev(&m), MetadataExt::ino(&m)))
}

/// An event format that writes `<N>` (the priority of the event's level) before what the inner format writes.
pub struct JournalPriority<F>(pub F);

impl<S, N, F> FormatEvent<S, N> for JournalPriority<F>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
    F: FormatEvent<S, N>,
{
    fn format_event(&self, ctx: &FmtContext<'_, S, N>, mut writer: Writer<'_>, event: &Event<'_>) -> fmt::Result {
        write!(writer, "<{}>", priority(event.metadata().level()))?;
        self.0.format_event(ctx, writer, event)
    }
}

/// The agent's subscriber: no ANSI, no time (journald stamps the lines), no target; `<N>` when stdout is the journal.
pub fn init() {
    let base = tracing_subscriber::fmt::format().with_ansi(false).without_time().with_target(false);
    let b = tracing_subscriber::fmt().with_ansi(false).with_writer(std::io::stdout);
    if stdout_is_journal() {
        b.event_format(JournalPriority(base)).init();
    } else {
        b.event_format(base).init();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The lines the agent's format writes for the events of `f`, with or without the journal prefix.
    fn capture(prefix: bool, f: impl FnOnce()) -> String {
        let buf = Buf(Arc::new(Mutex::new(Vec::new())));
        let w = buf.clone();
        let base = tracing_subscriber::fmt::format().with_ansi(false).without_time().with_target(false);
        let b = tracing_subscriber::fmt().with_ansi(false).with_writer(move || w.clone());
        if prefix {
            tracing::subscriber::with_default(b.event_format(JournalPriority(base)).finish(), f);
        } else {
            tracing::subscriber::with_default(b.event_format(base).finish(), f);
        }
        let out = buf.0.lock().unwrap().clone();
        String::from_utf8(out).unwrap()
    }

    fn events() {
        tracing::warn!(target: "audit", method = "Rollback", cn = "op1", "denied");
        tracing::error!("config apply failed");
        tracing::info!("config applied");
    }

    #[test]
    fn levels_map_to_syslog_priorities() {
        assert_eq!(
            [Level::ERROR, Level::WARN, Level::INFO, Level::DEBUG, Level::TRACE].map(|l| priority(&l)),
            [3, 4, 6, 7, 7]
        );
    }

    #[test]
    fn audit_warn_line_is_priority_4_in_the_journal() {
        let out = capture(true, events);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3, "{out}");
        assert!(lines[0].starts_with("<4>") && lines[0].contains("WARN") && lines[0].contains("denied"), "{out}");
        assert!(lines[0].contains("method=\"Rollback\""), "{out}");
        assert!(lines[1].starts_with("<3>") && lines[1].contains("ERROR"), "{out}");
        assert!(lines[2].starts_with("<6>") && lines[2].contains("INFO"), "{out}");
    }

    #[test]
    fn no_prefix_outside_the_journal_and_the_text_is_the_same() {
        let plain = capture(false, events);
        let journal = capture(true, events);
        assert!(plain.lines().all(|l| !l.starts_with('<')), "{plain}");
        // the prefix is the only difference: the rest of every line is what the agent wrote before
        let stripped: Vec<&str> = journal.lines().map(|l| &l[3..]).collect();
        assert_eq!(stripped, plain.lines().collect::<Vec<_>>());
    }

    #[test]
    fn journal_stream_names_stdouts_device_and_inode() {
        assert!(journal_stream_is("24:123456", 24, 123456));
        assert!(!journal_stream_is("24:123457", 24, 123456));
        assert!(!journal_stream_is("25:123456", 24, 123456));
        assert!(!journal_stream_is("24", 24, 123456));
        assert!(!journal_stream_is("", 24, 123456));
        assert!(!journal_stream_is("x:y", 24, 123456));
    }
}
