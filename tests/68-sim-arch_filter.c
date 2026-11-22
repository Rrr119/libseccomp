#include <errno.h>
#include <stddef.h>
#include <unistd.h>

#include <seccomp.h>

#include "util.h"

static int _bpf_size(const scmp_filter_ctx ctx, uint32_t arch_token,
		     size_t *len)
{
	*len = 0;
	return seccomp_export_bpf_mem_arch(ctx, arch_token, NULL, len);
}

static int _scenario_native_scope(void)
{
	int rc;
	size_t len;
	scmp_filter_ctx ctx;

	ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL)
		return -ENOMEM;

	rc = seccomp_rule_add_arch(ctx, SCMP_ARCH_NATIVE, SCMP_ACT_ALLOW,
				   SCMP_SYS(read), 0);
	if (rc == 0)
		rc = _bpf_size(ctx, SCMP_ARCH_NATIVE, &len);
	if (rc == 0 && len == 0)
		rc = -EFAULT;

	seccomp_release(ctx);
	return rc;
}

static int _scenario_arch_isolation(void)
{
	int rc;
	size_t len;
	int pfd[2];
	scmp_filter_ctx ctx;

	ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL)
		return -ENOMEM;

	rc = seccomp_arch_remove(ctx, SCMP_ARCH_NATIVE);
	if (rc == 0)
		rc = seccomp_arch_add(ctx, SCMP_ARCH_X86);
	if (rc == 0)
		rc = seccomp_arch_add(ctx, SCMP_ARCH_X86_64);
	if (rc == 0)
		rc = seccomp_rule_add_arch(ctx, SCMP_ARCH_X86, SCMP_ACT_ALLOW,
					   SCMP_SYS(read), 0);

	if (rc == 0)
		rc = _bpf_size(ctx, SCMP_ARCH_X86, &len);
	if (rc == 0)
		rc = _bpf_size(ctx, SCMP_ARCH_X86_64, &len);
	if (rc == 0) {
		rc = pipe(pfd);
		if (rc == 0) {
			rc = seccomp_export_pfc_arch(ctx, SCMP_ARCH_X86, pfd[1]);
			close(pfd[1]);
			if (rc == 0) {
				char buf[64];

				rc = (read(pfd[0], buf, sizeof(buf)) > 0) ?
				     0 : -EFAULT;
			}
			close(pfd[0]);
		}
	}

	seccomp_release(ctx);
	return rc;
}

static int _scenario_missing_or_invalid_arch(void)
{
	int rc;
	size_t len;
	scmp_filter_ctx ctx;

	ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL)
		return -ENOMEM;

	rc = seccomp_arch_remove(ctx, SCMP_ARCH_NATIVE);
	if (rc == 0)
		rc = seccomp_arch_add(ctx, SCMP_ARCH_X86);
	if (rc == 0)
		rc = seccomp_rule_add_arch(ctx, SCMP_ARCH_ARM, SCMP_ACT_ALLOW,
					   SCMP_SYS(read), 0);
	if (rc != -EEXIST)
		rc = (rc == 0 ? -EFAULT : rc);
	else
		rc = 0;
	if (rc == 0) {
		len = 0;
		rc = seccomp_export_bpf_mem_arch(ctx, SCMP_ARCH_ARM, NULL, &len);
		if (rc != -EEXIST)
			rc = (rc == 0 ? -EFAULT : rc);
		else
			rc = 0;
	}
	if (rc == 0) {
		len = 0;
		rc = seccomp_export_bpf_mem_arch(ctx, 0x7fffffff, NULL, &len);
		if (rc != -EINVAL)
			rc = (rc == 0 ? -EFAULT : rc);
		else
			rc = 0;
	}

	seccomp_release(ctx);
	return rc;
}

static int _scenario_exact_scoped_rule(void)
{
	int rc;
	scmp_filter_ctx ctx;

	ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL)
		return -ENOMEM;

	rc = seccomp_arch_remove(ctx, SCMP_ARCH_NATIVE);
	if (rc == 0)
		rc = seccomp_arch_add(ctx, SCMP_ARCH_X86);
	if (rc == 0)
		rc = seccomp_arch_add(ctx, SCMP_ARCH_X86_64);
	if (rc == 0)
		rc = seccomp_rule_add_exact_arch(ctx, SCMP_ARCH_X86,
						 SCMP_ACT_ALLOW,
						 SCMP_SYS(getpid), 0);
	if (rc == 0) {
		rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW,
					    SCMP_SYS(getpid), 0);
		if (rc != -EOPNOTSUPP)
			rc = (rc == 0 ? -EFAULT : rc);
		else
			rc = 0;
	}

	seccomp_release(ctx);
	return rc;
}

static int _scenario_duplicate_rule_optimization(void)
{
	int rc;
	size_t len_first, len_dup;
	scmp_filter_ctx ctx;

	ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL)
		return -ENOMEM;

	rc = seccomp_arch_remove(ctx, SCMP_ARCH_NATIVE);
	if (rc == 0)
		rc = seccomp_arch_add(ctx, SCMP_ARCH_X86_64);
	if (rc == 0)
		rc = seccomp_rule_add_arch(ctx, SCMP_ARCH_X86_64,
					   SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
	if (rc == 0)
		rc = _bpf_size(ctx, SCMP_ARCH_X86_64, &len_first);
	if (rc == 0)
		rc = seccomp_rule_add_arch(ctx, SCMP_ARCH_X86_64,
					   SCMP_ACT_ALLOW, SCMP_SYS(openat), 0);
	if (rc == 0)
		rc = _bpf_size(ctx, SCMP_ARCH_X86_64, &len_dup);
	if (rc == 0 && len_first != len_dup)
		rc = -EFAULT;

	seccomp_release(ctx);
	return rc;
}

int main(int argc, char *argv[])
{
	int rc;
	struct util_options opts;
	scmp_filter_ctx ctx = NULL;

	rc = util_getopt(argc, argv, &opts);
	if (rc < 0)
		goto out;

	/* Scenario 1: SCMP_ARCH_NATIVE resolves to the native filter. */
	rc = _scenario_native_scope();
	if (rc != 0)
		goto out;
	/* Scenario 2: a rule scoped to one ABI can be exported on its own. */
	rc = _scenario_arch_isolation();
	if (rc != 0)
		goto out;
	/* Scenario 3: missing and invalid architecture tokens are rejected. */
	rc = _scenario_missing_or_invalid_arch();
	if (rc != 0)
		goto out;
	/* Scenario 4: exact rules are valid when scoped to one architecture. */
	rc = _scenario_exact_scoped_rule();
	if (rc != 0)
		goto out;
	/* Scenario 5: duplicate rules do not grow the generated program. */
	rc = _scenario_duplicate_rule_optimization();
	if (rc != 0)
		goto out;

	ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL)
		return ENOMEM;

	rc = seccomp_arch_remove(ctx, SCMP_ARCH_NATIVE);
	if (rc != 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_X86);
	if (rc != 0)
		goto out;
	rc = seccomp_arch_add(ctx, SCMP_ARCH_X86_64);
	if (rc != 0)
		goto out;

	/* The legacy API continues to apply rules to every architecture. */
	rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
	if (rc != 0)
		goto out;

	/* Architecture-scoped rules are isolated to their target ABI. */
	rc = seccomp_rule_add_arch(ctx, SCMP_ARCH_X86, SCMP_ACT_ALLOW,
				   SCMP_SYS(read), 0);
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add_arch(ctx, SCMP_ARCH_X86_64, SCMP_ACT_ALLOW,
				   SCMP_SYS(close), 0);
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add_exact_arch(ctx, SCMP_ARCH_X86, SCMP_ACT_ALLOW,
					 SCMP_SYS(getpid), 0);
	if (rc != 0)
		goto out;

	/* The broader rule replaces the earlier argument-specific rule. */
	rc = seccomp_rule_add_arch(ctx, SCMP_ARCH_X86_64, SCMP_ACT_ALLOW,
				   SCMP_SYS(openat), 1,
				   SCMP_A0(SCMP_CMP_EQ, 42));
	if (rc != 0)
		goto out;
	rc = seccomp_rule_add_arch(ctx, SCMP_ARCH_X86_64, SCMP_ACT_ERRNO(77),
				   SCMP_SYS(openat), 0);
	if (rc != 0)
		goto out;

	rc = util_filter_output(&opts, ctx);
	if (rc)
		goto out;

out:
	seccomp_release(ctx);
	return (rc < 0 ? -rc : rc);
}
