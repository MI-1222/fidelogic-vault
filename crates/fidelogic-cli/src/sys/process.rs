//! # プロセス硬化 (`sys::process`)
//!
//! 起動直後にプロセス全体へ適用する OS レベルの保護を提供する。
//! 秘密情報がコアダンプやデバッガー経由でプロセス外へ漏れる経路を、引数の解析より前に塞ぐ。
//!
//! ## 適用する保護
//!
//! | 保護 | 対象 | 内容 |
//! | :-- | :-- | :-- |
//! | コアダンプの抑止 | POSIX 全般 | `RLIMIT_CORE` のソフト上限・ハード上限をともに 0 にする |
//! | ファイル作成権限の制限 | POSIX 全般 | `umask(0077)` で新規ファイルをオーナー専用にする |
//! | ダンプ・アタッチの拒否 | Linux | `PR_SET_DUMPABLE = 0` を設定し、`PR_GET_DUMPABLE` で確認する |
//! | デバッガーのアタッチ拒否 | macOS のリリースビルド | `ptrace(PT_DENY_ATTACH)` を呼び出す |
//!
//! いずれかの保護を適用できなかった場合は、保護が黙って弱まることを避けるため、
//! [`HardeningError`] を返して呼び出し元に処理の中断を求める。
//!
//! ## Notes
//!
//! - macOS のデバッグビルドで `PT_DENY_ATTACH` を呼ばないのは、開発時のデバッガー利用を妨げないためである。
//! - Linux で `PR_SET_DUMPABLE = 0` を設定すると、`/proc/self/` 配下のエントリの所有者が root になる。
//!   自プロセスの `/proc/self/fd/N` を開き直す実装は避け、ファイルディスクリプターは番号のまま扱う。
//! - `RLIMIT_CORE` のハード上限を下げる操作は、一般ユーザーには元へ戻せない。

// 本クレートで `unsafe` を許すのは、OS の API を直接呼び出す `sys` 配下のモジュールに限る。
#![allow(unsafe_code)]

use core::fmt;

/// プロセス硬化の個々の手順。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardeningStep {
    /// `RLIMIT_CORE` によるコアダンプの抑止。
    CoreLimit,
    /// `umask(0077)` によるファイル作成権限の制限。
    Umask,
    /// Linux の `PR_SET_DUMPABLE = 0` によるダンプ・アタッチの拒否。
    Dumpable,
    /// macOS の `PT_DENY_ATTACH` によるデバッガーのアタッチ拒否。
    DenyAttach,
}

impl HardeningStep {
    /// 手順の名称を日本語で返す。
    const fn label(self) -> &'static str {
        match self {
            Self::CoreLimit => "コアダンプの抑止 (RLIMIT_CORE)",
            Self::Umask => "ファイル作成権限の制限 (umask)",
            Self::Dumpable => "ダンプ・アタッチの拒否 (PR_SET_DUMPABLE)",
            Self::DenyAttach => "デバッガーのアタッチ拒否 (PT_DENY_ATTACH)",
        }
    }
}

/// プロセス硬化の失敗を表すエラー。
///
/// 秘密情報は含まない。`errno` は OS が返したエラー番号であり、診断のためだけに保持する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardeningError {
    /// OS の API 呼び出しが失敗した。
    Os {
        /// 失敗した手順。
        step: HardeningStep,
        /// OS が返したエラー番号。取得できなかった場合は 0。
        errno: i32,
    },
    /// 設定した後に読み戻した値が、期待した保護の状態になっていなかった。
    NotApplied {
        /// 確認に失敗した手順。
        step: HardeningStep,
    },
}

impl fmt::Display for HardeningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Os { step, errno } => {
                write!(f, "{}に失敗しました (errno: {errno})。", step.label())
            }
            Self::NotApplied { step } => {
                write!(
                    f,
                    "{}が適用されたことを確認できませんでした。",
                    step.label()
                )
            }
        }
    }
}

impl std::error::Error for HardeningError {}

/// 本プロセスが新規ファイルに適用する `umask` の値。オーナー以外の権限をすべて落とす。
const HARDENED_UMASK: libc::mode_t = 0o077;

/// コアダンプの上限がソフト・ハードともに 0 であるかを判定する。
///
/// # Args
///
/// - `limit`: `getrlimit(RLIMIT_CORE)` が返した値。
///
/// # Returns
///
/// ソフト上限とハード上限がともに 0 なら `true`。
fn core_limit_is_disabled(limit: &libc::rlimit) -> bool {
    limit.rlim_cur == 0 && limit.rlim_max == 0
}

/// `PR_GET_DUMPABLE` の戻り値が「ダンプ不可」を示すかを判定する。
///
/// # Args
///
/// - `value`: `prctl(PR_GET_DUMPABLE)` の戻り値。
///
/// # Returns
///
/// 値が 0 (ダンプ不可) なら `true`。1 (ダンプ可)、2 (管理者のみ可)、負数 (エラー) は `false`。
#[cfg(target_os = "linux")]
fn dumpable_is_disabled(value: libc::c_int) -> bool {
    value == 0
}

/// 直前に失敗した OS の API が返したエラー番号を取得する。取得できなければ 0 を返す。
fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// プロセス全体へ硬化を適用する。
///
/// 引数の解析や秘密情報の読み込みより前に、プロセスの起動直後に 1 度だけ呼び出す。
/// 複数回呼び出しても結果は変わらない。
///
/// # Errors
///
/// いずれかの保護を適用できなかった、または適用後の状態を確認できなかった場合は
/// [`HardeningError`] を返す。呼び出し元は処理を中断すること。
pub fn harden_process() -> Result<(), HardeningError> {
    disable_core_dumps()?;
    restrict_umask()?;
    #[cfg(target_os = "linux")]
    disable_dumpable()?;
    #[cfg(all(target_os = "macos", not(debug_assertions)))]
    deny_debugger_attach()?;
    Ok(())
}

/// `RLIMIT_CORE` のソフト・ハード上限をともに 0 にし、読み戻して確認する。
fn disable_core_dumps() -> Result<(), HardeningError> {
    let zero_limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `zero_limit` は有効な `rlimit` 構造体への参照であり、呼び出しの間は生存している。
    // `setrlimit` はこのポインターを読み取るだけで、保持しない。
    let result = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &zero_limit) };
    if result != 0 {
        return Err(HardeningError::Os {
            step: HardeningStep::CoreLimit,
            errno: last_errno(),
        });
    }

    let mut current = libc::rlimit {
        rlim_cur: libc::rlim_t::MAX,
        rlim_max: libc::rlim_t::MAX,
    };
    // SAFETY: `current` は書き込み可能な有効な `rlimit` 構造体であり、呼び出しの間は生存している。
    // `getrlimit` はこのポインターへ書き込むだけで、保持しない。
    let result = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut current) };
    if result != 0 {
        return Err(HardeningError::Os {
            step: HardeningStep::CoreLimit,
            errno: last_errno(),
        });
    }
    if core_limit_is_disabled(&current) {
        Ok(())
    } else {
        Err(HardeningError::NotApplied {
            step: HardeningStep::CoreLimit,
        })
    }
}

/// `umask(0077)` を設定し、再度の呼び出しで直前の値を読み戻して確認する。
fn restrict_umask() -> Result<(), HardeningError> {
    // SAFETY: `umask` はプロセスの属性を更新するだけで、メモリを参照せず、失敗しない。
    unsafe { libc::umask(HARDENED_UMASK) };
    // SAFETY: 同上。戻り値は直前の `umask` であり、上の設定が反映されていれば `HARDENED_UMASK` と一致する。
    let previous = unsafe { libc::umask(HARDENED_UMASK) };
    if previous == HARDENED_UMASK {
        Ok(())
    } else {
        Err(HardeningError::NotApplied {
            step: HardeningStep::Umask,
        })
    }
}

/// Linux で `PR_SET_DUMPABLE = 0` を設定し、`PR_GET_DUMPABLE` で確認する。
#[cfg(target_os = "linux")]
fn disable_dumpable() -> Result<(), HardeningError> {
    // SAFETY: `PR_SET_DUMPABLE` は整数引数のみを取り、ポインターを参照しない。`prctl` は可変長引数で `unsigned long` を読むため、未使用の引数も `c_ulong` の 0 で渡す。
    let result = unsafe {
        libc::prctl(
            libc::PR_SET_DUMPABLE,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if result != 0 {
        return Err(HardeningError::Os {
            step: HardeningStep::Dumpable,
            errno: last_errno(),
        });
    }

    // SAFETY: `PR_GET_DUMPABLE` は引数を参照せず、現在の設定値を戻り値として返す。
    let value = unsafe {
        libc::prctl(
            libc::PR_GET_DUMPABLE,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if value < 0 {
        return Err(HardeningError::Os {
            step: HardeningStep::Dumpable,
            errno: last_errno(),
        });
    }
    if dumpable_is_disabled(value) {
        Ok(())
    } else {
        Err(HardeningError::NotApplied {
            step: HardeningStep::Dumpable,
        })
    }
}

/// macOS で `ptrace(PT_DENY_ATTACH)` を呼び出し、デバッガーのアタッチを拒否する。
#[cfg(all(target_os = "macos", not(debug_assertions)))]
fn deny_debugger_attach() -> Result<(), HardeningError> {
    // SAFETY: `PT_DENY_ATTACH` は自プロセスの属性を更新するだけで、`pid`, `addr`, `data` を参照しない。
    // ポインター引数には null を渡す。
    let result = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, core::ptr::null_mut(), 0) };
    if result == 0 {
        Ok(())
    } else {
        Err(HardeningError::Os {
            step: HardeningStep::DenyAttach,
            errno: last_errno(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limit(soft: libc::rlim_t, hard: libc::rlim_t) -> libc::rlimit {
        libc::rlimit {
            rlim_cur: soft,
            rlim_max: hard,
        }
    }

    #[test]
    fn test_core_limit_is_disabled_accepts_zero_soft_and_hard() {
        assert!(
            core_limit_is_disabled(&limit(0, 0)),
            "ソフト・ハードがともに 0 の上限を無効と判定することに失敗。"
        );
    }

    #[test]
    fn test_core_limit_is_disabled_rejects_nonzero_soft() {
        assert!(
            !core_limit_is_disabled(&limit(1, 0)),
            "ソフト上限が 0 でない場合を有効と判定することに失敗。"
        );
    }

    #[test]
    fn test_core_limit_is_disabled_rejects_nonzero_hard() {
        assert!(
            !core_limit_is_disabled(&limit(0, 1)),
            "ハード上限が 0 でない場合を有効と判定することに失敗。"
        );
    }

    #[test]
    fn test_core_limit_is_disabled_rejects_unlimited() {
        assert!(
            !core_limit_is_disabled(&limit(libc::RLIM_INFINITY, libc::RLIM_INFINITY)),
            "無制限の上限を有効と判定することに失敗。"
        );
    }

    #[test]
    fn test_core_limit_is_disabled_rejects_maximum_hard() {
        assert!(
            !core_limit_is_disabled(&limit(0, libc::rlim_t::MAX)),
            "ハード上限が最大値の場合を有効と判定することに失敗。"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_dumpable_is_disabled_accepts_only_zero() {
        let cases = [
            (0, true, "ダンプ不可"),
            (1, false, "ダンプ可"),
            (2, false, "管理者のみダンプ可"),
            (-1, false, "エラー"),
        ];
        for (value, expected, name) in cases {
            assert_eq!(
                dumpable_is_disabled(value),
                expected,
                "{name} (値 {value}) の判定に失敗。"
            );
        }
    }

    #[test]
    fn test_error_display_ends_with_japanese_period() {
        let errors = [
            HardeningError::Os {
                step: HardeningStep::CoreLimit,
                errno: 1,
            },
            HardeningError::NotApplied {
                step: HardeningStep::Umask,
            },
        ];
        for error in errors {
            assert!(
                error.to_string().ends_with('。'),
                "エラーメッセージの末尾が句点でないため失敗しました: {error}"
            );
        }
    }

    #[test]
    fn test_error_display_includes_step_and_errno() {
        let message = HardeningError::Os {
            step: HardeningStep::DenyAttach,
            errno: 13,
        }
        .to_string();
        assert!(
            message.contains("PT_DENY_ATTACH") && message.contains("13"),
            "手順名と errno をメッセージに含めることに失敗しました: {message}"
        );
    }
}
