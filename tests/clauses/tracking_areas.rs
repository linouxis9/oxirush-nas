//! The 5GS tracking area identity (TS 24.501 §9.11.3.8): a TAC of all ones but its
//! least significant bit marks the TAI as deleted.

use oxirush_nas::identity::Plmn;
use oxirush_nas::nas_5gs::TrackingAreaIdentity;

#[test]
fn a_tai_is_deleted_by_its_tac() {
    let plmn = Plmn::new("208", "93").unwrap();
    let assigned = TrackingAreaIdentity::from_plmn_tac(&plmn, 1).unwrap();
    assert!(!assigned.is_deleted());
    let deleted = TrackingAreaIdentity::new(vec![0x02, 0xf8, 0x39, 0xff, 0xff, 0xfe]);
    assert!(deleted.is_deleted());
}
