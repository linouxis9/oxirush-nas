//! The S-NSSAI location validity information (TS 24.501 §9.11.3.100): up to 16
//! entries after their length of two octets, each an S-NSSAI after its length, the
//! number of NR CGIs in two octets, 1 to 300, and the NR CGIs, each an NR cell
//! identity of 36 bits in five octets and a PLMN. A receiver of a type 6 IE container
//! (§9.11.3.98) takes it when its syntax is right. The S-NSSAI time validity
//! information (§9.11.3.101): entries after their length of one octet, each an
//! S-NSSAI after its length and its time windows after their length, each window of
//! 16, 17 or 25 octets: the start and the stop time, the recurrence pattern, and the
//! end of the recurrence.

use oxirush_nas::identity::Plmn;
use oxirush_nas::nas_5gs::{
    NasSNssai, NasSNssaiLocationValidityInformation as Validity,
    NasSNssaiTimeValidityInformation as TimeValidity, NasType6IeContainer,
    SNssaiLocationValidityEntry as Entry, SNssaiLocationValidityNrCgi as NrCgi,
    SNssaiTimeValidityEntry as TimeEntry, SNssaiTimeWindow as Window,
    SNssaiTimeWindowRecurrencePattern as Pattern,
};

/// An NR CGI of the cell 0x123456789 of PLMN 208 93, in octets.
const CGI: &str = "1234567890 02f839";

fn octets(text: &str) -> Vec<u8> {
    hex::decode(text.split_whitespace().collect::<String>()).unwrap()
}

/// An entry of the S-NSSAI `snssai` (in octets) and of `count` NR CGIs, in octets.
fn entry(snssai: &str, count: usize) -> String {
    let snssai = octets(snssai);
    let length = 1 + snssai.len() + 2 + 8 * count;
    format!(
        "{length:04x} {:02x} {} {count:04x} {}",
        snssai.len(),
        hex::encode(&snssai),
        CGI.repeat(count)
    )
}

fn cgi() -> NrCgi {
    NrCgi {
        nr_cell_id: [0x12, 0x34, 0x56, 0x78, 0x90],
        plmn: Plmn::new("208", "93").unwrap(),
    }
}

/// Whether a type 6 IE container takes `value` as the S-NSSAI location validity
/// information (IEI 2).
fn taken(value: &[u8]) -> bool {
    let mut container = vec![0x02];
    container.extend((value.len() as u16).to_be_bytes());
    container.extend(value);
    !NasType6IeContainer::new(container).entries().is_empty()
}

#[test]
fn an_entry_has_its_s_nssai_and_its_nr_cgis() {
    let value = octets(&format!("{} {}", entry("01", 1), entry("02000007", 2)));
    let information = Validity::new(value.clone());
    let entries = vec![
        Entry::new(NasSNssai::new(vec![0x01]), vec![cgi()]),
        Entry::new(
            NasSNssai::new(vec![0x02, 0x00, 0x00, 0x07]),
            vec![cgi(), cgi()],
        ),
    ];
    assert_eq!(information.entries(), entries);
    assert!(information.is_well_formed());
    assert_eq!(Validity::from_entries(&entries).unwrap().value, value);
    assert!(taken(&value));
    // The spare bits of the NR cell identity are not read
    let spare = octets(&entry("01", 1).replace("1234567890", "123456789f"));
    assert_eq!(Validity::new(spare).entries(), entries[..1]);
    // 300 NR CGIs at most
    let most = Validity::new(octets(&entry("01", 300)));
    assert_eq!(most.entries()[0].nr_cgis.len(), 300);
    assert!(
        Validity::new(octets(&entry("01", 301)))
            .entries()
            .is_empty()
    );
    assert!(!taken(&octets(&entry("01", 301))));
    // Sixteen entries at most
    let seventeen = octets(&entry("01", 1).repeat(17));
    assert_eq!(Validity::new(seventeen.clone()).entries().len(), 16);
    assert!(!taken(&seventeen));
    assert!(taken(&octets(&entry("01", 1).repeat(16))));
}

#[test]
fn an_entry_cut_short_or_without_nr_cgi_is_not_read() {
    let first = entry("01", 1);
    for second in [
        // No NR CGI
        "0004 01 01 0000".to_string(),
        // An entry longer than the IE, whose NR CGI has no PLMN
        "00ff 01 01 0001 1234567890".to_string(),
        // An entry that ends after its S-NSSAI, and an S-NSSAI past its entry
        "0002 01 01".to_string(),
        "0002 05 01".to_string(),
    ] {
        let value = octets(&format!("{first} {second}"));
        let read = Validity::new(value.clone()).entries();
        assert_eq!(
            read,
            [Entry::new(NasSNssai::new(vec![0x01]), vec![cgi()])],
            "{second}"
        );
        assert!(!taken(&value), "{second}");
    }
    // An NR CGI cut short by the end of its entry, followed by another entry
    let short = format!("000b 01 01 0001 {}", &CGI[..CGI.len() - 2]);
    let read = Validity::new(octets(&format!("{short} {first}"))).entries();
    assert!(read.is_empty());
}

#[test]
fn a_recurrence_pattern_is_one_of_its_ten_codes() {
    let patterns = [
        Pattern::Everyday,
        Pattern::EveryWeekday,
        Pattern::EveryWeek,
        Pattern::EveryTwoWeeks,
        Pattern::EveryMonthAbsolute,
        Pattern::EveryMonthRelative,
        Pattern::EveryQuarterAbsolute,
        Pattern::EveryQuarterRelative,
        Pattern::EverySixMonthsAbsolute,
        Pattern::EverySixMonthsRelative,
    ];
    for code in 0..16u8 {
        let pattern = patterns.get(usize::from(code)).copied();
        assert_eq!(Pattern::from_u8(code), pattern, "{code}");
    }
}

/// The start and the stop time of a window, in octets.
const TIMES: &str = "0101010101010101 0202020202020202";

/// An entry of the S-NSSAI `snssai` and the time windows `windows`, in octets.
fn time_entry(snssai: &str, windows: &[&str]) -> String {
    let snssai = octets(snssai);
    let windows: Vec<u8> = windows.iter().flat_map(|window| octets(window)).collect();
    let length = 1 + snssai.len() + 1 + windows.len();
    format!(
        "{length:02x} {:02x} {} {:02x} {}",
        snssai.len(),
        hex::encode(&snssai),
        windows.len(),
        hex::encode(&windows)
    )
}

#[test]
fn a_time_window_has_the_fields_of_its_length() {
    let window = |pattern, end| Window::new([1; 8], [2; 8], pattern, end);
    let windows = [
        format!("10 {TIMES}"),
        format!("11 {TIMES} 03"),
        format!("19 {TIMES} 09 0303030303030303"),
    ];
    let windows: Vec<&str> = windows.iter().map(String::as_str).collect();
    let value = octets(&format!(
        "{} {}",
        time_entry("01", &windows),
        time_entry("02000007", &windows[..1])
    ));
    let entries = vec![
        TimeEntry::new(
            NasSNssai::new(vec![0x01]),
            vec![
                window(None, None),
                window(Some(Pattern::EveryTwoWeeks), None),
                window(Some(Pattern::EverySixMonthsRelative), Some([3; 8])),
            ],
        ),
        TimeEntry::new(
            NasSNssai::new(vec![0x02, 0x00, 0x00, 0x07]),
            vec![window(None, None)],
        ),
    ];
    assert_eq!(TimeValidity::new(value).entries(), entries);
    // A window of a length that is none of the three ends the windows of its entry
    let odd = format!("12 {TIMES} 0300");
    let read = TimeValidity::new(octets(&time_entry("01", &[&odd, windows[0]]))).entries();
    assert_eq!(read, [TimeEntry::new(NasSNssai::new(vec![0x01]), vec![])]);
    // An octet after the time windows of an entry is not read
    let mut trailing = octets(&time_entry("02000007", &windows[..1]));
    trailing[0] += 1;
    trailing.push(0xff);
    assert_eq!(TimeValidity::new(trailing).entries(), entries[1..]);
    // A window after the end of the time information, within its entry, is not read
    let window = &windows[0];
    let after = octets(&format!("25 01 01 11 {window} {window}"));
    let read = TimeValidity::new(after).entries();
    assert_eq!(read.len(), 1);
    assert_eq!(read[0].time_windows.len(), 1);
}

#[test]
fn a_time_entry_cut_short_is_not_read() {
    let window = format!("10 {TIMES}");
    let whole = octets(&time_entry("01", &[&window]));
    // An entry one octet longer than the IE, and an S-NSSAI beyond the end of the IE
    let mut longer = whole.clone();
    longer[0] += 1;
    assert!(TimeValidity::new(longer).entries().is_empty());
    assert!(TimeValidity::new(octets("02 04 01")).entries().is_empty());
}
