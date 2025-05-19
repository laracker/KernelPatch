#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <syscall.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/random.h>
#include <kputils.h>
#include <asm/current.h>

#include "hidefeature.h"

KPM_NAME("hidefeature");
KPM_VERSION("1.0.0");
KPM_AUTHOR("larack");
KPM_DESCRIPTION("hide features in mounts and maps | args {hook, unhook}");


// 关键词列表
static struct filter_keyword filter_keywords[MAX_FILTER_KEYWORDS] = {
    { .keyword = "adb", .len = 0 },
    { .keyword = "module", .len = 0 },
    { .keyword = "rwxp", .len = 0 },//自己添加的
    { .keyword = "lsposed", .len = 0 },//自己添加的
    // 可在此添加更多关键词，剩余的保持为 NULL
};
static size_t num_keywords = 4; // 当前有效关键词数量

typedef int (*vfs_show_func_t)(struct seq_file *, struct vfsmount *);
typedef void (*map_show_func_t)(struct seq_file *, struct vm_area_struct *);
typedef int (*smap_show_func_t)(struct seq_file *, void *);

static hook_err_t hook_err = HOOK_NO_ERR;

static vfs_show_func_t ori_show_vfsmnt, backup_show_vfsmnt;
static vfs_show_func_t ori_show_mountinfo, backup_show_mountinfo;
static vfs_show_func_t ori_show_vfsstat, backup_show_vfsstat;
static map_show_func_t ori_show_map_vma, backup_show_map_vma;
static smap_show_func_t ori_show_smap, backup_show_smap;

static void *(*kf_vmalloc)(unsigned long size);
static void (*kf_vfree)(const void *addr);
static struct mm_struct *(*kf_get_task_mm)(struct task_struct *task);

static inline void print_info(void) {
    pr_info("Kernel Version: %x, Patch Version: %x\n", kver, kpver);
}

static inline bool is_proc_effective(void) {
    return kf_get_task_mm && current && kf_get_task_mm(current);
}

static char get_random_char(void) {
    return RANDOM_CHARS[get_random_u64() % RANDOM_CHARS_LEN];
}

static void replace_sensitive(char *str, size_t len, const struct filter_keyword *keyword) {
    char *pos;
    while ((pos = strnstr(str, keyword->keyword, len)) != NULL) {
        size_t offset = pos - str;
        for (size_t i = 0; i < keyword->len && (offset + i < len); i++) {
            if (keyword->keyword[i] != '/' || str[offset + i] != '/') {
                str[offset + i] = get_random_char();
            }
        }
        str += offset + keyword->len;
        len -= offset + keyword->len;
    }
}

static inline bool contains_keyword(char *str, size_t len) {
    for (size_t i = 0; i < num_keywords; i++) {
        if (strnstr(str, filter_keywords[i].keyword, len)) {
            return true;
        }
    }
    return false;
}

static inline bool filter_output(struct seq_file *m, size_t old_count, bool replace) {
    if (m->count <= old_count) return false;

    char *buf_start = m->buf + old_count;
    size_t len = m->count - old_count;

    if (contains_keyword(buf_start, len)) {
        if (replace) {
            for (size_t i = 0; i < num_keywords; i++) {
                replace_sensitive(buf_start, len, &filter_keywords[i]);
            }
        } else {
            m->count = old_count;
        }
        return true;
    }
    return false;
}

static int rep_show_vfsmnt(struct seq_file *m, struct vfsmount *mnt) {
    if (!is_proc_effective()) return 0;
    size_t old_count = m->count;
    int ret = backup_show_vfsmnt(m, mnt);
    if (ret == 0) filter_output(m, old_count, false);
    return ret;
}

static int rep_show_mountinfo(struct seq_file *m, struct vfsmount *mnt) {
    if (!is_proc_effective()) return 0;
    size_t old_count = m->count;
    int ret = backup_show_mountinfo(m, mnt);
    if (ret == 0) filter_output(m, old_count, true);
    return ret;
}

static int rep_show_vfsstat(struct seq_file *m, struct vfsmount *mnt) {
    if (!is_proc_effective()) return 0;
    size_t old_count = m->count;
    int ret = backup_show_vfsstat(m, mnt);
    if (ret == 0) filter_output(m, old_count, false);
    return ret;
}

static void rep_show_map_vma(struct seq_file *m, struct vm_area_struct *vma) {
    if (!is_proc_effective()) return;
    size_t old_count = m->count;
    backup_show_map_vma(m, vma);
    filter_output(m, old_count, false);
}

static int rep_show_smap(struct seq_file *m, void *v) {
    if (!is_proc_effective()) return 0;
    size_t old_count = m->count;
    int ret = backup_show_smap(m, v);
    if (ret == 0) filter_output(m, old_count, false);
    return ret;
}

static bool hook_all(void) {
    struct hook_funcs hooks[] = {
        { ori_show_vfsmnt, rep_show_vfsmnt, (void **)&backup_show_vfsmnt },
        { ori_show_mountinfo, rep_show_mountinfo, (void **)&backup_show_mountinfo },
        { ori_show_vfsstat, rep_show_vfsstat, (void **)&backup_show_vfsstat },
        { ori_show_map_vma, rep_show_map_vma, (void **)&backup_show_map_vma },
        { ori_show_smap, rep_show_smap, (void **)&backup_show_smap },
    };

    for (size_t i = 0; i < ARRAY_SIZE(hooks); i++) {
        if (!hooks[i].original) {
            pr_err("[yuuki] missing symbol for hook %zu\n", i);
            return false;
        }
        hook_err = hook(hooks[i].original, hooks[i].replacement, hooks[i].backup);
        if (hook_err != HOOK_NO_ERR) {
            pr_err("[yuuki] hook failed at %zu\n", i);
            return false;
        }
    }
    return true;
}

static inline bool install_hook(void) {
    if (hook_err == HOOK_NO_ERR) {
        pr_info("[yuuki] hook already installed, skipping...\n");
        return true;
    }
    if (hook_all()) {
        pr_info("[yuuki] hook installed...\n");
        return true;
    }
    pr_err("[yuuki] hook installation failed...\n");
    return false;
}

static inline bool uninstall_hook(void) {
    if (hook_err != HOOK_NO_ERR) {
        pr_info("[yuuki] not hooked, skipping...\n");
        return true;
    }
    unhook(ori_show_vfsmnt);
    unhook(ori_show_mountinfo);
    unhook(ori_show_vfsstat);
    unhook(ori_show_map_vma);
    unhook(ori_show_smap);
    hook_err = HOOK_NOT_HOOK;
    pr_info("[yuuki] hook uninstalled...\n");
    return true;
}

static inline bool control_hook(bool enable) {
    return enable ? install_hook() : uninstall_hook();
}

static long mod_init(const char *args, const char *event, void *__user reserved) {
    pr_info("[yuuki] Initializing...\n");
    print_info();

    // 初始化关键词长度
    for (size_t i = 0; i < num_keywords; i++) {
        filter_keywords[i].len = strlen(filter_keywords[i].keyword);
    }

    static const char *syms[] = {"show_vfsmnt", "show_mountinfo", "show_vfsstat", "show_map_vma", "show_smap"};
    void *funcs[] = {(void *)&ori_show_vfsmnt, (void *)&ori_show_mountinfo, (void *)&ori_show_vfsstat,
                      (void *)&ori_show_map_vma, (void *)&ori_show_smap};

    for (size_t i = 0; i < ARRAY_SIZE(syms); i++) {
        *(void **)funcs[i] = (void *)kallsyms_lookup_name(syms[i]);
        if (!*(void **)funcs[i]) {
            pr_err("[yuuki] symbol %s not found\n", syms[i]);
        }
    }

    kf_vmalloc = (void *)kallsyms_lookup_name("vmalloc");
    kf_vfree = (void *)kallsyms_lookup_name("vfree");
    kf_get_task_mm = (void *)kallsyms_lookup_name("get_task_mm");

    if (!kf_vmalloc || !kf_vfree) {
        pr_err("[yuuki] kernel func vmalloc/vfree missing\n");
    }
    return 0;
}

static long mod_control0(const char *args, char *__user out_msg, int outlen) {
    pr_info("[yuuki] kpm_control0, args: %s\n", args);

    if (strcmp(args, "hook") == 0)
        control_hook(true);
    else if(strcmp(args, "unhook") == 0)
        control_hook(false);
    else{
        char echo[64] = "unknown: ";
        strncat(echo, args, 48);
        compat_copy_to_user(out_msg, echo, sizeof(echo));
    }

    return 0;
}

static long mod_exit(void *__user reserved) {
    control_hook(false);
    pr_info("[yuuki] mod_exit, uninstalled hook.\n");
    return 0;
}

KPM_INIT(mod_init);
KPM_CTL0(mod_control0);
KPM_EXIT(mod_exit);