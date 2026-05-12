//! Recomp stealth hook 桥接层
//!
//! 页管理在 agent 侧（mmap/prctl），本模块通过注册的回调访问。
//! JS API 的 hook("recomp") 模式通过本模块触发页重编译 + 地址翻译。

pub mod page;

pub use page::{
    alloc_trampoline_slot, commit_slot_patch, ensure_and_translate, fixup_slot_trampoline, install_patch,
    patch_suspend_polls, revert_slot_patch, set_alloc_slot_handler, set_cleanup_release_only, set_commit_handler,
    set_fixup_handler, set_handler, set_install_patch_handler, set_patch_suspend_polls_handler,
    set_reverse_translate_handler, set_revert_handler, set_translate_existing_handler, set_try_revert_handler,
    set_try_revert_slot_handler, translate_existing, translate_recomp_to_orig, try_revert_slot_patch,
    try_revert_slot_patch_by_slot,
};
