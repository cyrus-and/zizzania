#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "handler.h"
#include "terminal.h"

int zz_drop_root(zz_handler *zz) {
    const char *sudo_user;
    uid_t uid;
    gid_t gid;

    /* nothing to do for non-root users */
    if (getuid() != 0) {
        zz_log("User not root, nothing to do");
        return 1;
    }

    /* if from sudo restore credential */
    sudo_user = getenv("SUDO_USER");
    if (sudo_user) {
        const char *id;

        zz_log("Running with sudo, becoming '%s'", sudo_user);

        /* restore user id */
        id = getenv("SUDO_UID");
        if (!id) {
            zz_error(zz, "SUDO_UID not defined");
            return 0;
        }
        uid = atoi(id);

        /* restore group id */
        id = getenv("SUDO_GID");
        if (!id) {
            zz_error(zz, "SUDO_GID not defined");
        }
        gid = atoi(id);
    }
    /* otherwise become nobody */
    else {
        struct passwd *nobody;

        zz_log("Becoming 'nobody'");
        nobody = getpwnam("nobody");
        uid = nobody->pw_uid;
        gid = nobody->pw_gid;
    }

    /* set permissions (group first!) */
    if (setgroups(0, NULL) != 0 || setgid(gid) != 0 || setuid(uid) != 0) {
        zz_error(zz, "Cannot switch user %u:%u", uid, gid);
        return 0;
    }

    return 1;
}
