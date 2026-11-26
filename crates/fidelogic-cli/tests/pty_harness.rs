//! 疑似端末を使うテストの共通部分 (`common`) の、`openpty` をやり直す条件のテスト。
//!
//! 実際の `openpty` の失敗は任意に起こせないため、失敗を返す処理に差し替えて確かめる。

mod common;

use std::io;

use common::{OPENPTY_ATTEMPTS, TRANSIENT_OPENPTY_ERRNO, retry_transient_openpty};

/// 先頭の `failures` 回は `errno` で失敗し、その後は成功する処理を実行する。
///
/// 結果 (成功した場合は何回目の呼び出しか)、呼び出した回数、やり直しの通知で受けた回数の列を返す。
fn run(failures: u32, errno: i32) -> (Result<u32, Option<i32>>, u32, Vec<u32>) {
    let mut calls = 0;
    let mut reported = Vec::new();
    let result = retry_transient_openpty(
        || {
            calls += 1;
            if calls <= failures {
                Err(io::Error::from_raw_os_error(errno))
            } else {
                Ok(calls)
            }
        },
        |attempt| reported.push(attempt),
    );
    (
        result.map_err(|error| error.raw_os_error()),
        calls,
        reported,
    )
}

#[test]
fn test_transient_openpty_failure_is_retried_and_reported() {
    for failures in [0, 1, OPENPTY_ATTEMPTS - 1] {
        let expected: Vec<u32> = (1..=failures).collect();
        assert_eq!(
            run(failures, TRANSIENT_OPENPTY_ERRNO),
            (Ok(failures + 1), failures + 1, expected),
            "{failures} 回の失敗のやり直しに失敗。"
        );
    }
}

#[test]
fn test_persistent_openpty_failure_stops_at_limit() {
    let expected: Vec<u32> = (1..OPENPTY_ATTEMPTS).collect();
    for failures in [OPENPTY_ATTEMPTS, u32::MAX] {
        assert_eq!(
            run(failures, TRANSIENT_OPENPTY_ERRNO),
            (
                Err(Some(TRANSIENT_OPENPTY_ERRNO)),
                OPENPTY_ATTEMPTS,
                expected.clone()
            ),
            "上限での中止の確認に失敗。"
        );
    }
}

#[test]
fn test_other_openpty_failures_are_not_retried() {
    for errno in [libc::EMFILE, libc::ENXIO, libc::EINTR, -5, -7] {
        assert_eq!(
            run(1, errno),
            (Err(Some(errno)), 1, Vec::new()),
            "errno {errno} をやり直さないことの確認に失敗。"
        );
    }

    // OS のエラー番号を持たない失敗。
    let mut calls = 0;
    let result: io::Result<()> = retry_transient_openpty(
        || {
            calls += 1;
            Err(io::Error::other("not an os error"))
        },
        |_| {},
    );
    assert!(result.is_err() && calls == 1);
}
