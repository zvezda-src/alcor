DISTCHECK_CONFIGURE_FLAGS = --enable-haskell-tests

abs_top_builddir = @abs_top_builddir@
abs_top_srcdir = @abs_top_srcdir@

empty :=
space := $(empty) $(empty)
comma := ,

strip_hsroot = $(patsubst src/%,%,$(patsubst test/hs/%,%,$(1)))

SHELL=/bin/bash

EXTRA_DIST=

SHELLTESTARGS = "-c"

UTF8_LOCALE := $(shell locale -a | grep -m 1 -xF "C.UTF-8" || echo "en_US.UTF-8")

ACLOCAL_AMFLAGS = -I autotools
BUILD_BASH_COMPLETION = $(top_srcdir)/autotools/build-bash-completion
RUN_IN_TEMPDIR = $(top_srcdir)/autotools/run-in-tempdir
CHECK_PYTHON_CODE = $(top_srcdir)/autotools/check-python-code
CHECK_HEADER = $(top_srcdir)/autotools/check-header
CHECK_MAN_DASHES = $(top_srcdir)/autotools/check-man-dashes
CHECK_MAN_REFERENCES = $(top_srcdir)/autotools/check-man-references
CHECK_MAN_WARNINGS = $(top_srcdir)/autotools/check-man-warnings
CHECK_VERSION = $(top_srcdir)/autotools/check-version
CHECK_NEWS = $(top_srcdir)/autotools/check-news
CHECK_IMPORTS = $(top_srcdir)/autotools/check-imports
DOCPP = $(top_srcdir)/autotools/docpp
REPLACE_VARS_SED = autotools/replace_vars.sed
PRINT_PY_CONSTANTS = $(top_srcdir)/autotools/print-py-constants
BUILD_RPC = $(top_srcdir)/autotools/build-rpc
SHELL_ENV_INIT = autotools/shell-env-init

if USE_VERSION_FULL
DIRVERSION=$(VERSION_FULL)
else
DIRVERSION=$(VERSION_MAJOR).$(VERSION_MINOR)
endif
versiondir = $(libdir)/alcor/$(DIRVERSION)
defaultversiondir = $(libdir)/alcor/default
versionedsharedir = $(prefix)/share/alcor/$(DIRVERSION)
defaultversionedsharedir = $(prefix)/share/alcor/default

pkglibdir = $(versiondir)$(libdir)/alcor
myexeclibdir = $(pkglibdir)
bindir = $(versiondir)/$(BINDIR)
sbindir = $(versiondir)$(SBINDIR)
mandir = $(versionedsharedir)/root$(MANDIR)
pkgpythondir = $(versionedsharedir)/alcor
pkgpython_rpc_stubdir = $(versionedsharedir)/alcor/rpc/stub
gntpythondir = $(versionedsharedir)
pkgpython_bindir = $(versionedsharedir)
gnt_python_sbindir = $(versionedsharedir)
tools_pythondir = $(versionedsharedir)

clientdir = $(pkgpythondir)/client
cmdlibdir = $(pkgpythondir)/cmdlib
cmdlib_clusterdir = $(pkgpythondir)/cmdlib/cluster
configdir = $(pkgpythondir)/config
hypervisordir = $(pkgpythondir)/hypervisor
hypervisor_hv_kvmdir = $(pkgpythondir)/hypervisor/hv_kvm
jqueuedir = $(pkgpythondir)/jqueue
storagedir = $(pkgpythondir)/storage
httpdir = $(pkgpythondir)/http
masterddir = $(pkgpythondir)/masterd
confddir = $(pkgpythondir)/confd
rapidir = $(pkgpythondir)/rapi
rpcdir = $(pkgpythondir)/rpc
rpc_stubdir = $(pkgpythondir)/rpc/stub
serverdir = $(pkgpythondir)/server
watcherdir = $(pkgpythondir)/watcher
impexpddir = $(pkgpythondir)/impexpd
utilsdir = $(pkgpythondir)/utils
toolsdir = $(pkglibdir)/tools
iallocatorsdir = $(pkglibdir)/iallocators
pytoolsdir = $(pkgpythondir)/tools
docdir = $(versiondir)$(datadir)/doc/$(PACKAGE)
ifupdir = $(sysconfdir)/alcor

if USE_BACKUP_DIR
backup_dir = $(BACKUP_DIR)
else
backup_dir = $(localstatedir)/lib
endif

SYMLINK_TARGET_DIRS = \
	$(sysconfdir)/alcor \
	$(libdir)/alcor/iallocators \
	$(libdir)/alcor/tools \
	$(prefix)/share/alcor \
	$(BINDIR) \
	$(SBINDIR) \
	$(MANDIR)/man1 \
	$(MANDIR)/man7 \
	$(MANDIR)/man8

.DELETE_ON_ERROR:

HS_DIRS = \
	src \
	src/Alcor \
	src/Alcor/Confd \
	src/Alcor/Curl \
	src/Alcor/Cpu \
	src/Alcor/DataCollectors \
	src/Alcor/Daemon \
	src/Alcor/Hs2Py \
	src/Alcor/HTools \
	src/Alcor/HTools/Backend \
	src/Alcor/HTools/Cluster \
	src/Alcor/HTools/Program \
	src/Alcor/HTools/Tags \
	src/Alcor/Hypervisor \
	src/Alcor/Hypervisor/Xen \
	src/Alcor/JQScheduler \
	src/Alcor/JQueue \
	src/Alcor/Locking \
	src/Alcor/Logging \
	src/Alcor/MaintD \
	src/Alcor/Metad \
	src/Alcor/Monitoring \
	src/Alcor/Objects \
	src/Alcor/OpCodes \
	src/Alcor/Query \
	src/Alcor/Storage \
	src/Alcor/Storage/Diskstats \
	src/Alcor/Storage/Drbd \
	src/Alcor/Storage/Lvm \
	src/Alcor/THH \
	src/Alcor/Utils \
	src/Alcor/WConfd \
	test/hs \
	test/hs/Test \
	test/hs/Test/Alcor \
	test/hs/Test/Alcor/Storage \
	test/hs/Test/Alcor/Storage/Diskstats \
	test/hs/Test/Alcor/Storage/Drbd \
	test/hs/Test/Alcor/Storage/Lvm \
	test/hs/Test/Alcor/Confd \
	test/hs/Test/Alcor/HTools \
	test/hs/Test/Alcor/HTools/Backend \
	test/hs/Test/Alcor/Hypervisor \
	test/hs/Test/Alcor/Hypervisor/Xen \
	test/hs/Test/Alcor/JQueue \
	test/hs/Test/Alcor/Locking \
	test/hs/Test/Alcor/Objects \
	test/hs/Test/Alcor/Query \
	test/hs/Test/Alcor/THH \
	test/hs/Test/Alcor/Utils \
	test/hs/Test/Alcor/WConfd

HS_DIRS_NOROOT = $(filter-out src,$(filter-out test/hs,$(HS_DIRS)))

DIRS = \
	$(HS_DIRS) \
	autotools \
	cabal \
	daemons \
	devel \
	devel/data \
	doc \
	doc/css \
	doc/examples \
	doc/examples/gnt-debug \
	doc/examples/hooks \
	doc/examples/systemd \
	doc/users \
	test/data/htools \
	test/data/htools/rapi \
	test/hs/shelltests \
	test/autotools \
	lib \
	lib/build \
	lib/client \
	lib/cmdlib \
	lib/cmdlib/cluster \
	lib/confd \
	lib/config \
	lib/jqueue \
	lib/http \
	lib/hypervisor \
	lib/hypervisor/hv_kvm \
	lib/impexpd \
	lib/masterd \
	lib/rapi \
	lib/rpc \
	lib/rpc/stub \
	lib/server \
	lib/storage \
	lib/tools \
	lib/utils \
	lib/watcher \
	man \
	qa \
	qa/patch \
	test \
	test/data \
	test/data/bdev-rbd \
	test/data/ovfdata \
	test/data/ovfdata/other \
	test/data/cgroup_root \
	test/data/cgroup_root/memory \
	test/data/cgroup_root/memory/lxc \
	test/data/cgroup_root/memory/lxc/instance1 \
	test/data/cgroup_root/cpuset \
	test/data/cgroup_root/cpuset/some_group \
	test/data/cgroup_root/cpuset/some_group/lxc \
	test/data/cgroup_root/cpuset/some_group/lxc/instance1 \
	test/data/cgroup_root/devices \
	test/data/cgroup_root/devices/some_group \
	test/data/cgroup_root/devices/some_group/lxc \
	test/data/cgroup_root/devices/some_group/lxc/instance1 \
	test/py \
	test/py/testutils \
	test/py/cmdlib \
	test/py/cmdlib/testsupport \
	tools

ALL_APIDOC_HS_DIRS = \
	$(APIDOC_HS_DIR) \
	$(patsubst %,$(APIDOC_HS_DIR)/%,$(call strip_hsroot,$(HS_DIRS_NOROOT)))

BUILDTIME_DIR_AUTOCREATE = \
	scripts \
	$(APIDOC_DIR) \
	$(ALL_APIDOC_HS_DIRS) \
	$(APIDOC_PY_DIR) \
	$(COVERAGE_DIR) \
	$(COVERAGE_HS_DIR) \
	$(COVERAGE_PY_DIR) \
	.hpc

BUILDTIME_DIRS = \
	$(BUILDTIME_DIR_AUTOCREATE) \
	apps \
	dist \
	dist/build \
	doc/html \
	doc/man-html

DIRCHECK_EXCLUDE = \
	$(BUILDTIME_DIRS) \
	alcor-[0-9]*.[0-9]*.[0-9]* \
	doc/html/_* \
	doc/man-html/_* \
	tools/shebang \
	autom4te.cache

COVERAGE_DIR = doc/coverage
COVERAGE_PY_DIR = $(COVERAGE_DIR)/py
COVERAGE_HS_DIR = $(COVERAGE_DIR)/hs
APIDOC_DIR = doc/api
APIDOC_PY_DIR = $(APIDOC_DIR)/py
APIDOC_HS_DIR = $(APIDOC_DIR)/hs

MAINTAINERCLEANFILES = \
	doc/install-quick.rst \
	doc/news.rst \
	doc/upgrade.rst \
	vcs-version

maintainer-clean-local:
	rm -rf $(BUILDTIME_DIRS)

CLEANFILES = \
	$(addsuffix /*.py[co],$(DIRS)) \
	$(addsuffix /*.hi,$(HS_DIRS)) \
	$(addsuffix /*.dyn_hi,$(HS_DIRS)) \
	$(addsuffix /*.o,$(HS_DIRS)) \
	$(addsuffix /*.dyn_o,$(HS_DIRS)) \
	$(addsuffix /*.$(HTEST_SUFFIX)_hi,$(HS_DIRS)) \
	$(addsuffix /*.$(HTEST_SUFFIX)_o,$(HS_DIRS)) \
	$(HASKELL_PACKAGE_VERSIONS_FILE) \
	$(CABAL_EXECUTABLES_APPS_STAMPS) \
	empty-cabal-config \
	alcor.cabal \
	$(HASKELL_PACKAGE_IDS_FILE) \
	$(HASKELL_PACKAGE_VERSIONS_FILE) \
	Makefile.ghc \
	Makefile.ghc.bak \
	$(PYTHON_BOOTSTRAP) \
	$(gnt_python_sbin_SCRIPTS) \
	$(REPLACE_VARS_SED) \
	$(SHELL_ENV_INIT) \
	daemons/daemon-util \
	daemons/alcor-cleaner \
	devel/squeeze-amd64.tar.gz \
	devel/squeeze-amd64.conf \
	$(mandocrst) \
	doc/manpages-enabled.rst \
	$(BUILT_EXAMPLES) \
	doc/examples/bash_completion \
	doc/examples/bash_completion-debug \
	$(userspecs) \
	lib/_generated_rpc.py \
	$(man_MANS) \
	$(manhtml) \
	tools/kvm-ifup \
	tools/kvm-ifup-os \
	tools/xen-ifup-os \
	tools/vif-alcor \
	tools/vif-alcor-metad \
	tools/net-common \
	tools/users-setup \
	tools/ssl-update \
	tools/vcluster-setup \
	tools/prepare-node-join \
	tools/ssh-update \
	$(python_scripts_shebang) \
	stamp-directories \
	stamp-srclinks \
	$(nodist_pkgpython_PYTHON) \
	$(nodist_pkgpython_rpc_stub_PYTHON) \
	$(gnt_scripts) \
	$(HS_ALL_PROGS) $(HS_BUILT_SRCS) \
	$(HS_BUILT_TEST_HELPERS) \
	src/alcor-confd \
	src/alcor-wconfd \
	src/alcor-luxid \
	src/alcor-metad \
	src/alcor-mond \
	.hpc/*.mix src/*.tix test/hs/*.tix *.tix \
	doc/hs-lint.html

GENERATED_FILES = \
	$(built_base_sources) \
	$(built_python_sources) \
	$(PYTHON_BOOTSTRAP) \
	$(gnt_python_sbin_SCRIPTS)

clean-local:
	rm -rf tools/shebang
	rm -rf apps
	rm -rf dist
	find -D exec . -type d -name __pycache__ -exec rm -rf {} +

HS_GENERATED_FILES = $(HS_PROGS) src/hluxid src/alcor-luxid \
	src/hconfd src/alcor-confd
if ENABLE_MOND
HS_GENERATED_FILES += src/alcor-mond
endif
if ENABLE_METADATA
HS_GENERATED_FILES += src/alcor-metad
endif

built_base_sources = \
	stamp-directories \
	stamp-srclinks

built_python_base_sources = \
	lib/_constants.py \
	lib/_vcsversion.py \
	lib/opcodes.py \
	lib/rpc/stub/wconfd.py

if ENABLE_METADATA
built_python_base_sources += lib/rpc/stub/metad.py
endif

built_python_sources = \
	$(nodist_pkgpython_PYTHON) \
	$(nodist_pkgpython_rpc_stub_PYTHON)

BUILT_EXAMPLES = \
	doc/examples/alcor-kvm-poweroff.initd \
	doc/examples/alcor.cron \
	doc/examples/alcor.initd \
	doc/examples/alcor.logrotate \
	doc/examples/alcor-master-role.ocf \
	doc/examples/alcor-node-role.ocf \
	doc/examples/gnt-config-backup \
	doc/examples/hooks/ipsec \
	doc/examples/systemd/alcor-common.service \
	doc/examples/systemd/alcor-confd.service \
	doc/examples/systemd/alcor-kvmd.service \
	doc/examples/systemd/alcor-luxid.service \
	doc/examples/systemd/alcor-metad.service \
	doc/examples/systemd/alcor-mond.service \
	doc/examples/systemd/alcor-noded.service \
	doc/examples/systemd/alcor-rapi.service \
	doc/examples/systemd/alcor-wconfd.service

nodist_ifup_SCRIPTS = \
	tools/kvm-ifup-os \
	tools/xen-ifup-os

nodist_pkgpython_PYTHON = \
	$(built_python_base_sources) \
	lib/_generated_rpc.py

nodist_pkgpython_rpc_stub_PYTHON = \
	lib/rpc/stub/wconfd.py

if ENABLE_METADATA
nodist_pkgpython_rpc_stub_PYTHON += lib/rpc/stub/metad.py
endif

nodist_pkgpython_bin_SCRIPTS = \
	$(nodist_pkglib_python_scripts)

pkgpython_bin_SCRIPTS = \
	$(pkglib_python_scripts)

noinst_PYTHON = \
	lib/build/__init__.py \
	lib/build/shell_example_lexer.py \
	lib/build/sphinx_ext.py

pkgpython_PYTHON = \
	lib/__init__.py \
	lib/asyncnotifier.py \
	lib/backend.py \
	lib/bootstrap.py \
	lib/cli.py \
	lib/cli_opts.py \
	lib/compat.py \
	lib/constants.py \
	lib/daemon.py \
	lib/errors.py \
	lib/hooksmaster.py \
	lib/ht.py \
	lib/jstore.py \
	lib/locking.py \
	lib/luxi.py \
	lib/mcpu.py \
	lib/metad.py \
	lib/netutils.py \
	lib/objects.py \
	lib/opcodes_base.py \
	lib/outils.py \
	lib/ovf.py \
	lib/pathutils.py \
	lib/qlang.py \
	lib/query.py \
	lib/rpc_defs.py \
	lib/runtime.py \
	lib/serializer.py \
	lib/ssconf.py \
	lib/ssh.py \
	lib/uidpool.py \
	lib/vcluster.py \
	lib/network.py \
	lib/wconfd.py \
	lib/workerpool.py

client_PYTHON = \
	lib/client/__init__.py \
	lib/client/base.py \
	lib/client/gnt_backup.py \
	lib/client/gnt_cluster.py \
	lib/client/gnt_debug.py \
	lib/client/gnt_group.py \
	lib/client/gnt_instance.py \
	lib/client/gnt_job.py \
	lib/client/gnt_node.py \
	lib/client/gnt_network.py \
	lib/client/gnt_os.py \
	lib/client/gnt_storage.py \
	lib/client/gnt_filter.py

cmdlib_PYTHON = \
	lib/cmdlib/__init__.py \
	lib/cmdlib/backup.py \
	lib/cmdlib/base.py \
	lib/cmdlib/common.py \
	lib/cmdlib/group.py \
	lib/cmdlib/instance.py \
	lib/cmdlib/instance_create.py \
	lib/cmdlib/instance_helpervm.py \
	lib/cmdlib/instance_migration.py \
	lib/cmdlib/instance_operation.py \
	lib/cmdlib/instance_query.py \
	lib/cmdlib/instance_set_params.py \
	lib/cmdlib/instance_storage.py \
	lib/cmdlib/instance_utils.py \
	lib/cmdlib/misc.py \
	lib/cmdlib/network.py \
	lib/cmdlib/node.py \
	lib/cmdlib/operating_system.py \
	lib/cmdlib/query.py \
	lib/cmdlib/tags.py \
	lib/cmdlib/test.py

cmdlib_cluster_PYTHON = \
	lib/cmdlib/cluster/__init__.py \
	lib/cmdlib/cluster/verify.py

config_PYTHON = \
	lib/config/__init__.py \
	lib/config/verify.py \
	lib/config/temporary_reservations.py \
	lib/config/utils.py

hypervisor_PYTHON = \
	lib/hypervisor/__init__.py \
	lib/hypervisor/hv_base.py \
	lib/hypervisor/hv_chroot.py \
	lib/hypervisor/hv_fake.py \
	lib/hypervisor/hv_lxc.py \
	lib/hypervisor/hv_xen.py

hypervisor_hv_kvm_PYTHON = \
	lib/hypervisor/hv_kvm/__init__.py \
	lib/hypervisor/hv_kvm/monitor.py \
	lib/hypervisor/hv_kvm/netdev.py \
	lib/hypervisor/hv_kvm/validation.py

jqueue_PYTHON = \
	lib/jqueue/__init__.py \
	lib/jqueue/exec.py

storage_PYTHON = \
	lib/storage/__init__.py \
	lib/storage/bdev.py \
	lib/storage/base.py \
	lib/storage/container.py \
	lib/storage/drbd.py \
	lib/storage/drbd_info.py \
	lib/storage/drbd_cmdgen.py \
	lib/storage/extstorage.py \
	lib/storage/filestorage.py \
	lib/storage/gluster.py

rapi_PYTHON = \
	lib/rapi/__init__.py \
	lib/rapi/baserlib.py \
	lib/rapi/client.py \
	lib/rapi/client_utils.py \
	lib/rapi/connector.py \
	lib/rapi/rlib2.py \
	lib/rapi/testutils.py

http_PYTHON = \
	lib/http/__init__.py \
	lib/http/auth.py \
	lib/http/client.py \
	lib/http/server.py

confd_PYTHON = \
	lib/confd/__init__.py \
	lib/confd/client.py

masterd_PYTHON = \
	lib/masterd/__init__.py \
	lib/masterd/iallocator.py \
	lib/masterd/instance.py

impexpd_PYTHON = \
	lib/impexpd/__init__.py

watcher_PYTHON = \
	lib/watcher/__init__.py \
	lib/watcher/nodemaint.py \
	lib/watcher/state.py

server_PYTHON = \
	lib/server/__init__.py \
	lib/server/masterd.py \
	lib/server/noded.py \
	lib/server/rapi.py

rpc_PYTHON = \
	lib/rpc/__init__.py \
	lib/rpc/client.py \
	lib/rpc/errors.py \
	lib/rpc/node.py \
	lib/rpc/transport.py

rpc_stub_PYTHON = \
	lib/rpc/stub/__init__.py

pytools_PYTHON = \
	lib/tools/__init__.py \
	lib/tools/burnin.py \
	lib/tools/common.py \
	lib/tools/ensure_dirs.py \
	lib/tools/node_cleanup.py \
	lib/tools/node_daemon_setup.py \
	lib/tools/prepare_node_join.py \
	lib/tools/ssh_update.py \
	lib/tools/ssl_update.py \
	lib/tools/cfgupgrade.py

utils_PYTHON = \
	lib/utils/__init__.py \
	lib/utils/algo.py \
	lib/utils/filelock.py \
	lib/utils/hash.py \
	lib/utils/io.py \
	lib/utils/livelock.py \
	lib/utils/log.py \
	lib/utils/lvm.py \
	lib/utils/mlock.py \
	lib/utils/nodesetup.py \
	lib/utils/process.py \
	lib/utils/retry.py \
	lib/utils/security.py \
	lib/utils/storage.py \
	lib/utils/text.py \
	lib/utils/tags.py \
	lib/utils/version.py \
	lib/utils/wrapper.py \
	lib/utils/x509.py \
	lib/utils/bitarrays.py

docinput = \
	doc/admin.rst \
	doc/cluster-keys-replacement.rst \
	doc/cluster-merge.rst \
	doc/conf.py \
	doc/design-2.0.rst \
	doc/design-2.1.rst \
	doc/design-2.2.rst \
	doc/design-2.3.rst \
	doc/design-2.4.rst \
	doc/design-2.5.rst \
	doc/design-2.6.rst \
	doc/design-2.7.rst \
	doc/design-2.8.rst \
	doc/design-2.9.rst \
	doc/design-2.10.rst \
	doc/design-2.11.rst \
	doc/design-2.12.rst \
	doc/design-2.13.rst \
	doc/design-2.14.rst \
	doc/design-2.15.rst \
	doc/design-2.16.rst \
	doc/design-3.0.rst \
	doc/design-allocation-efficiency.rst \
	doc/design-autorepair.rst \
	doc/design-bulk-create.rst \
	doc/design-ceph-alcor-support.rst \
	doc/design-configlock.rst \
	doc/design-chained-jobs.rst \
	doc/design-cmdlib-unittests.rst \
	doc/design-cpu-pinning.rst \
	doc/design-cpu-speed.rst \
	doc/design-daemons.rst \
	doc/design-dedicated-allocation.rst \
	doc/design-device-uuid-name.rst \
	doc/design-disk-conversion.rst \
	doc/design-disks.rst \
	doc/design-draft.rst \
	doc/design-file-based-disks-ownership.rst \
	doc/design-file-based-storage.rst \
	doc/design-glusterfs-alcor-support.rst \
	doc/design-hotplug.rst \
	doc/design-hroller.rst \
	doc/design-hsqueeze.rst \
	doc/design-htools-2.3.rst \
	doc/design-http-server.rst \
	doc/design-hugepages-support.rst \
	doc/design-ifdown.rst \
	doc/design-impexp2.rst \
	doc/design-internal-shutdown.rst \
	doc/design-kvmd.rst \
	doc/design-location.rst \
	doc/design-linuxha.rst \
	doc/design-lu-generated-jobs.rst \
	doc/design-monitoring-agent.rst \
	doc/design-move-instance-improvements.rst \
	doc/design-multi-reloc.rst \
	doc/design-multi-storage-htools.rst \
	doc/design-multi-version-tests.rst \
	doc/design-network.rst \
	doc/design-network2.rst \
	doc/design-node-add.rst \
	doc/design-node-security.rst \
	doc/design-oob.rst \
	doc/design-openvswitch.rst \
	doc/design-opportunistic-locking.rst \
	doc/design-optables.rst \
	doc/design-os.rst \
	doc/design-ovf-support.rst \
	doc/design-partitioned.rst \
	doc/design-plain-redundancy.rst \
	doc/design-performance-tests.rst \
	doc/design-query-splitting.rst \
	doc/design-query2.rst \
	doc/design-query-splitting.rst \
	doc/design-reason-trail.rst \
	doc/design-repaird.rst \
	doc/design-reservations.rst \
	doc/design-resource-model.rst \
	doc/design-restricted-commands.rst \
	doc/design-scsi-kvm.rst \
	doc/design-shared-storage.rst \
	doc/design-shared-storage-redundancy.rst \
	doc/design-ssh-ports.rst \
	doc/design-storagetypes.rst \
	doc/design-sync-rate-throttling.rst \
	doc/design-systemd.rst \
	doc/design-upgrade.rst \
	doc/design-virtual-clusters.rst \
	doc/design-x509-ca.rst \
	doc/dev-codestyle.rst \
	doc/devnotes.rst \
	doc/glossary.rst \
	doc/hooks.rst \
	doc/iallocator.rst \
	doc/index.rst \
	doc/install-quick.rst \
	doc/install.rst \
	doc/locking.rst \
	doc/manpages-disabled.rst \
	doc/monitoring-query-format.rst \
	doc/move-instance.rst \
	doc/news.rst \
	doc/ovfconverter.rst \
	doc/rapi.rst \
	doc/security.rst \
	doc/upgrade.rst \
	doc/virtual-cluster.rst \
	doc/walkthrough.rst

mandocrst = $(addprefix doc/man-,$(notdir $(manrst)))

HS_BIN_PROGS=src/htools

if ENABLE_MOND
HS_MYEXECLIB_PROGS=src/mon-collector
else
HS_MYEXECLIB_PROGS=
endif

HS_COMPILE_PROGS = \
	src/alcor-kvmd \
	src/alcor-wconfd \
	src/hconfd \
	src/hluxid \
	src/hs2py \
	src/rpc-test
if ENABLE_MOND
HS_COMPILE_PROGS += src/alcor-mond
endif
if ENABLE_METADATA
HS_COMPILE_PROGS += src/alcor-metad
endif

HS_PROGS = $(HS_BIN_PROGS) $(HS_MYEXECLIB_PROGS)

HS_BIN_ROLES = harep hbal hscan hspace hinfo hcheck hroller hsqueeze
HS_HTOOLS_PROGS = $(HS_BIN_ROLES) hail

HS_DEFAULT_PROGS = \
	$(HS_BIN_PROGS) \
	test/hs/hpc-htools \
	test/hs/hpc-mon-collector \
	$(HS_COMPILE_PROGS)

if HTEST
HS_DEFAULT_PROGS += test/hs/htest
else
EXTRA_DIST += test/hs/htest.hs
endif

HS_ALL_PROGS = $(HS_DEFAULT_PROGS) $(HS_MYEXECLIB_PROGS)

HS_TEST_PROGS = $(filter test/%,$(HS_ALL_PROGS))
HS_SRC_PROGS = $(filter-out test/%,$(HS_ALL_PROGS))

HS_PROG_SRCS = $(patsubst %,%.hs,$(HS_DEFAULT_PROGS)) src/mon-collector.hs
HS_BUILT_TEST_HELPERS = $(HS_BIN_ROLES:%=test/hs/%) test/hs/hail

HFLAGS = \
	-O -Wall -isrc \
	-fwarn-monomorphism-restriction \
	-fwarn-tabs \
	-optP-include -optP$(HASKELL_PACKAGE_VERSIONS_FILE) \
	-hide-all-packages \
	`cat $(HASKELL_PACKAGE_IDS_FILE)` \
	$(GHC_BYVERSION_FLAGS)

HTEST_SUFFIX = hpc
HPROF_SUFFIX = prof

DEP_SUFFIXES = -dep-suffix $(HPROF_SUFFIX)_ -dep-suffix $(HTEST_SUFFIX)_ \
	-dep-suffix ""

HFLAGS_DYNAMIC = -dynamic-too

if HPROFILE
HPROFFLAGS = -prof -fprof-auto-top -osuf $(HPROF_SUFFIX)_o \
	-hisuf $(HPROF_SUFFIX)_hi -rtsopts
endif
if HCOVERAGE
HFLAGS += -fhpc
endif
if HTEST
HFLAGS += -DTEST
endif

HTEST_FLAGS = $(HFLAGS) -fhpc -itest/hs \
	-osuf $(HTEST_SUFFIX)_o \
	-hisuf $(HTEST_SUFFIX)_hi

HEXTRA =
HEXTRA_COMBINED = $(HEXTRA) $(HEXTRA_CONFIGURE)

HEXTRA_TEST = -threaded -with-rtsopts="-N -A32m" -rtsopts

HPCEXCL = --exclude Main \
	--exclude Alcor.Constants \
	--exclude Alcor.HTools.QC \
	--exclude Alcor.THH \
	--exclude Alcor.Version \
	--exclude Test.Alcor.Attoparsec \
	--exclude Test.Alcor.TestCommon \
	--exclude Test.Alcor.TestHTools \
	--exclude Test.Alcor.TestHelper \
	--exclude Test.Alcor.TestImports \
	$(patsubst src.%,--exclude Test.%,$(subst /,.,$(patsubst %.hs,%, $(HS_LIB_SRCS))))

HS_LIB_SRCS = \
	src/Alcor/BasicTypes.hs \
	src/Alcor/Codec.hs \
	src/Alcor/Common.hs \
	src/Alcor/Compat.hs \
	src/Alcor/Confd/Client.hs \
	src/Alcor/Confd/ClientFunctions.hs \
	src/Alcor/Confd/Server.hs \
	src/Alcor/Confd/Types.hs \
	src/Alcor/Confd/Utils.hs \
	src/Alcor/Config.hs \
	src/Alcor/ConfigReader.hs \
	src/Alcor/Constants.hs \
	src/Alcor/ConstantUtils.hs \
	src/Alcor/Cpu/LoadParser.hs \
	src/Alcor/Cpu/Types.hs \
	src/Alcor/Curl/Multi.hs \
	src/Alcor/Daemon.hs \
	src/Alcor/Daemon/Utils.hs \
	src/Alcor/DataCollectors.hs \
	src/Alcor/DataCollectors/CLI.hs \
	src/Alcor/DataCollectors/CPUload.hs \
	src/Alcor/DataCollectors/Diskstats.hs \
	src/Alcor/DataCollectors/Drbd.hs \
	src/Alcor/DataCollectors/InstStatus.hs \
	src/Alcor/DataCollectors/InstStatusTypes.hs \
	src/Alcor/DataCollectors/Lv.hs \
	src/Alcor/DataCollectors/Program.hs \
	src/Alcor/DataCollectors/Types.hs \
	src/Alcor/DataCollectors/XenCpuLoad.hs \
	src/Alcor/Errors.hs \
	src/Alcor/HTools/AlgorithmParams.hs \
	src/Alcor/HTools/Backend/IAlloc.hs \
	src/Alcor/HTools/Backend/Luxi.hs \
	src/Alcor/HTools/Backend/MonD.hs \
	src/Alcor/HTools/Backend/Rapi.hs \
	src/Alcor/HTools/Backend/Simu.hs \
	src/Alcor/HTools/Backend/Text.hs \
	src/Alcor/HTools/CLI.hs \
	src/Alcor/HTools/Cluster.hs \
	src/Alcor/HTools/Cluster/AllocatePrimitives.hs \
	src/Alcor/HTools/Cluster/AllocateSecondary.hs \
	src/Alcor/HTools/Cluster/AllocationSolution.hs \
	src/Alcor/HTools/Cluster/Evacuate.hs \
	src/Alcor/HTools/Cluster/Metrics.hs \
	src/Alcor/HTools/Cluster/Moves.hs \
	src/Alcor/HTools/Cluster/Utils.hs \
	src/Alcor/HTools/Container.hs \
	src/Alcor/HTools/Dedicated.hs \
	src/Alcor/HTools/ExtLoader.hs \
	src/Alcor/HTools/GlobalN1.hs \
	src/Alcor/HTools/Graph.hs \
	src/Alcor/HTools/Group.hs \
	src/Alcor/HTools/Instance.hs \
	src/Alcor/HTools/Loader.hs \
	src/Alcor/HTools/Nic.hs \
	src/Alcor/HTools/Node.hs \
	src/Alcor/HTools/PeerMap.hs \
	src/Alcor/HTools/Program/Hail.hs \
	src/Alcor/HTools/Program/Harep.hs \
	src/Alcor/HTools/Program/Hbal.hs \
	src/Alcor/HTools/Program/Hcheck.hs \
	src/Alcor/HTools/Program/Hinfo.hs \
	src/Alcor/HTools/Program/Hscan.hs \
	src/Alcor/HTools/Program/Hspace.hs \
	src/Alcor/HTools/Program/Hsqueeze.hs \
	src/Alcor/HTools/Program/Hroller.hs \
	src/Alcor/HTools/Program/Main.hs \
	src/Alcor/HTools/Tags.hs \
	src/Alcor/HTools/Tags/Constants.hs \
	src/Alcor/HTools/Types.hs \
	src/Alcor/Hypervisor/Xen.hs \
	src/Alcor/Hypervisor/Xen/XlParser.hs \
	src/Alcor/Hypervisor/Xen/Types.hs \
	src/Alcor/Hash.hs \
	src/Alcor/Hs2Py/GenConstants.hs \
	src/Alcor/Hs2Py/GenOpCodes.hs \
	src/Alcor/Hs2Py/OpDoc.hs \
	src/Alcor/JQScheduler.hs \
	src/Alcor/JQScheduler/Filtering.hs \
	src/Alcor/JQScheduler/ReasonRateLimiting.hs \
	src/Alcor/JQScheduler/Types.hs \
	src/Alcor/JQueue.hs \
	src/Alcor/JQueue/Lens.hs \
	src/Alcor/JQueue/Objects.hs \
	src/Alcor/JSON.hs \
	src/Alcor/Jobs.hs \
	src/Alcor/Kvmd.hs \
	src/Alcor/Lens.hs \
	src/Alcor/Locking/Allocation.hs \
	src/Alcor/Locking/Types.hs \
	src/Alcor/Locking/Locks.hs \
	src/Alcor/Locking/Waiting.hs \
	src/Alcor/Logging.hs \
	src/Alcor/Logging/Lifted.hs \
	src/Alcor/Logging/WriterLog.hs \
	src/Alcor/Luxi.hs \
	src/Alcor/Network.hs \
	src/Alcor/Objects.hs \
	src/Alcor/Objects/BitArray.hs \
	src/Alcor/Objects/Disk.hs \
	src/Alcor/Objects/Instance.hs \
	src/Alcor/Objects/Lens.hs \
	src/Alcor/Objects/Nic.hs \
	src/Alcor/OpCodes.hs \
	src/Alcor/OpCodes/Lens.hs \
	src/Alcor/OpParams.hs \
	src/Alcor/Path.hs \
	src/Alcor/Parsers.hs \
	src/Alcor/PyValue.hs \
	src/Alcor/Query/Cluster.hs \
	src/Alcor/Query/Common.hs \
	src/Alcor/Query/Exec.hs \
	src/Alcor/Query/Export.hs \
	src/Alcor/Query/Filter.hs \
	src/Alcor/Query/FilterRules.hs \
	src/Alcor/Query/Group.hs \
	src/Alcor/Query/Instance.hs \
	src/Alcor/Query/Job.hs \
	src/Alcor/Query/Language.hs \
	src/Alcor/Query/Locks.hs \
	src/Alcor/Query/Network.hs \
	src/Alcor/Query/Node.hs \
	src/Alcor/Query/Query.hs \
	src/Alcor/Query/Server.hs \
	src/Alcor/Query/Types.hs \
	src/Alcor/PartialParams.hs \
	src/Alcor/Rpc.hs \
	src/Alcor/Runtime.hs \
	src/Alcor/SlotMap.hs \
	src/Alcor/Ssconf.hs \
	src/Alcor/Storage/Diskstats/Parser.hs \
	src/Alcor/Storage/Diskstats/Types.hs \
	src/Alcor/Storage/Drbd/Parser.hs \
	src/Alcor/Storage/Drbd/Types.hs \
	src/Alcor/Storage/Lvm/LVParser.hs \
	src/Alcor/Storage/Lvm/Types.hs \
	src/Alcor/Storage/Utils.hs \
	src/Alcor/THH.hs \
	src/Alcor/THH/Compat.hs \
	src/Alcor/THH/Field.hs \
	src/Alcor/THH/HsRPC.hs \
	src/Alcor/THH/PyRPC.hs \
	src/Alcor/THH/PyType.hs \
	src/Alcor/THH/Types.hs \
	src/Alcor/THH/RPC.hs \
	src/Alcor/Types.hs \
	src/Alcor/UDSServer.hs \
	src/Alcor/Utils.hs \
	src/Alcor/Utils/Atomic.hs \
	src/Alcor/Utils/AsyncWorker.hs \
	src/Alcor/Utils/IORef.hs \
	src/Alcor/Utils/Livelock.hs \
	src/Alcor/Utils/Monad.hs \
	src/Alcor/Utils/MultiMap.hs \
	src/Alcor/Utils/MVarLock.hs \
	src/Alcor/Utils/Random.hs \
	src/Alcor/Utils/Statistics.hs \
	src/Alcor/Utils/UniStd.hs \
	src/Alcor/Utils/Validate.hs \
	src/Alcor/VCluster.hs \
	src/Alcor/WConfd/ConfigState.hs \
	src/Alcor/WConfd/ConfigModifications.hs \
	src/Alcor/WConfd/ConfigVerify.hs \
	src/Alcor/WConfd/ConfigWriter.hs \
	src/Alcor/WConfd/Client.hs \
	src/Alcor/WConfd/Core.hs \
	src/Alcor/WConfd/DeathDetection.hs \
	src/Alcor/WConfd/Language.hs \
	src/Alcor/WConfd/Monad.hs \
	src/Alcor/WConfd/Persistent.hs \
	src/Alcor/WConfd/Server.hs \
	src/Alcor/WConfd/Ssconf.hs \
	src/Alcor/WConfd/TempRes.hs

if ENABLE_MOND
HS_LIB_SRCS += src/Alcor/Monitoring/Server.hs
else
EXTRA_DIST += src/Alcor/Monitoring/Server.hs
endif

if ENABLE_METADATA
HS_LIB_SRCS += \
	src/Alcor/Metad/Config.hs \
	src/Alcor/Metad/ConfigCore.hs \
	src/Alcor/Metad/ConfigServer.hs \
	src/Alcor/Metad/Server.hs \
	src/Alcor/Metad/Types.hs \
	src/Alcor/Metad/WebServer.hs
else
EXTRA_DIST += \
	src/Alcor/Metad/Config.hs \
	src/Alcor/Metad/ConfigCore.hs \
	src/Alcor/Metad/ConfigServer.hs \
	src/Alcor/Metad/Server.hs \
	src/Alcor/Metad/Types.hs \
	src/Alcor/Metad/WebServer.hs
endif

HS_TEST_SRCS = \
	test/hs/Test/AutoConf.hs \
	test/hs/Test/Alcor/Attoparsec.hs \
	test/hs/Test/Alcor/BasicTypes.hs \
	test/hs/Test/Alcor/Common.hs \
	test/hs/Test/Alcor/Confd/Types.hs \
	test/hs/Test/Alcor/Confd/Utils.hs \
	test/hs/Test/Alcor/Constants.hs \
	test/hs/Test/Alcor/Daemon.hs \
	test/hs/Test/Alcor/Errors.hs \
	test/hs/Test/Alcor/HTools/Backend/MonD.hs \
	test/hs/Test/Alcor/HTools/Backend/Simu.hs \
	test/hs/Test/Alcor/HTools/Backend/Text.hs \
	test/hs/Test/Alcor/HTools/CLI.hs \
	test/hs/Test/Alcor/HTools/Cluster.hs \
	test/hs/Test/Alcor/HTools/Container.hs \
	test/hs/Test/Alcor/HTools/Graph.hs \
	test/hs/Test/Alcor/HTools/Instance.hs \
	test/hs/Test/Alcor/HTools/Loader.hs \
	test/hs/Test/Alcor/HTools/Node.hs \
	test/hs/Test/Alcor/HTools/PeerMap.hs \
	test/hs/Test/Alcor/HTools/Types.hs \
	test/hs/Test/Alcor/Hypervisor/Xen/XlParser.hs \
	test/hs/Test/Alcor/JSON.hs \
	test/hs/Test/Alcor/Jobs.hs \
	test/hs/Test/Alcor/JQScheduler.hs \
	test/hs/Test/Alcor/JQueue.hs \
	test/hs/Test/Alcor/JQueue/Objects.hs \
	test/hs/Test/Alcor/Kvmd.hs \
	test/hs/Test/Alcor/Luxi.hs \
	test/hs/Test/Alcor/Locking/Allocation.hs \
	test/hs/Test/Alcor/Locking/Locks.hs \
	test/hs/Test/Alcor/Locking/Waiting.hs \
	test/hs/Test/Alcor/Network.hs \
	test/hs/Test/Alcor/PartialParams.hs \
	test/hs/Test/Alcor/PyValue.hs \
	test/hs/Test/Alcor/Objects.hs \
	test/hs/Test/Alcor/Objects/BitArray.hs \
	test/hs/Test/Alcor/OpCodes.hs \
	test/hs/Test/Alcor/Query/Aliases.hs \
	test/hs/Test/Alcor/Query/Filter.hs \
	test/hs/Test/Alcor/Query/Instance.hs \
	test/hs/Test/Alcor/Query/Language.hs \
	test/hs/Test/Alcor/Query/Network.hs \
	test/hs/Test/Alcor/Query/Query.hs \
	test/hs/Test/Alcor/Rpc.hs \
	test/hs/Test/Alcor/Runtime.hs \
	test/hs/Test/Alcor/SlotMap.hs \
	test/hs/Test/Alcor/Ssconf.hs \
	test/hs/Test/Alcor/Storage/Diskstats/Parser.hs \
	test/hs/Test/Alcor/Storage/Drbd/Parser.hs \
	test/hs/Test/Alcor/Storage/Drbd/Types.hs \
	test/hs/Test/Alcor/Storage/Lvm/LVParser.hs \
	test/hs/Test/Alcor/THH.hs \
	test/hs/Test/Alcor/THH/Types.hs \
	test/hs/Test/Alcor/TestCommon.hs \
	test/hs/Test/Alcor/TestHTools.hs \
	test/hs/Test/Alcor/TestHelper.hs \
	test/hs/Test/Alcor/Types.hs \
	test/hs/Test/Alcor/Utils.hs \
	test/hs/Test/Alcor/Utils/MultiMap.hs \
	test/hs/Test/Alcor/Utils/Statistics.hs \
	test/hs/Test/Alcor/WConfd/Ssconf.hs \
	test/hs/Test/Alcor/WConfd/TempRes.hs


HS_LIBTEST_SRCS = $(HS_LIB_SRCS) $(HS_TEST_SRCS)

HS_BUILT_SRCS = \
	test/hs/Test/Alcor/TestImports.hs \
	src/AutoConf.hs \
	src/Alcor/Hs2Py/ListConstants.hs \
	src/Alcor/Curl/Internal.hs \
	src/Alcor/Version.hs
HS_BUILT_SRCS_IN = \
	$(patsubst %,%.in,$(filter-out src/Alcor/Curl/Internal.hs,$(HS_BUILT_SRCS))) \
	src/Alcor/Curl/Internal.hsc \
	lib/_constants.py.in \
	lib/opcodes.py.in_after \
	lib/opcodes.py.in_before

HS_LIBTESTBUILT_SRCS = $(HS_LIBTEST_SRCS) $(HS_BUILT_SRCS)

$(RUN_IN_TEMPDIR): | stamp-directories

doc/html/index.html: ENABLE_MANPAGES =
doc/man-html/index.html: ENABLE_MANPAGES = 1
doc/man-html/index.html: doc/manpages-enabled.rst $(mandocrst)

doc/html/index.html doc/man-html/index.html: $(docinput) doc/conf.py \
	configure.ac $(RUN_IN_TEMPDIR) lib/build/sphinx_ext.py \
	lib/build/shell_example_lexer.py lib/ht.py \
	lib/rapi/connector.py lib/rapi/rlib2.py \
	$(abs_top_srcdir)/autotools/sphinx-wrapper | $(built_python_sources)
	@test -n "$(SPHINX)" || \
	    { echo 'sphinx-build' not found during configure; exit 1; }
if !MANPAGES_IN_DOC
	if test -n '$(ENABLE_MANPAGES)'; then \
	  echo 'Man pages in documentation were disabled at configure time' >&2; \
	  exit 1; \
	fi
endif
	dir=$(dir $@) && \
	@mkdir_p@ $$dir && \
	PYTHONPATH=. ENABLE_MANPAGES=$(ENABLE_MANPAGES) COPY_DOC=1 \
	$(RUN_IN_TEMPDIR) \
	    $(abs_top_srcdir)/autotools/sphinx-wrapper $(SPHINX) -q -W -b html \
		-d . \
		-D version="$(VERSION_MAJOR).$(VERSION_MINOR)" \
		-D release="$(PACKAGE_VERSION)" \
		-D graphviz_dot="$(DOT)" \
	doc $(CURDIR)/$$dir && \
	rm -f $$dir/.buildinfo $$dir/objects.inv
	touch $@

doc/html: doc/html/index.html

doc/man-html: doc/man-html/index.html

doc/install-quick.rst: INSTALL
doc/news.rst: NEWS
doc/upgrade.rst: UPGRADE

doc/install-quick.rst doc/news.rst doc/upgrade.rst:
	set -e; \
	{ echo '.. This file is automatically updated at build time from $<.'; \
	  echo '.. Do not edit.'; \
	  echo; \
	  cat $<; \
	} > $@

doc/manpages-enabled.rst: Makefile | $(built_base_sources)
	{ echo '.. This file is automatically generated, do not edit!'; \
	  echo ''; \
	  echo 'Man pages'; \
	  echo '========='; \
	  echo; \
	  echo '.. toctree::'; \
	  echo '   :maxdepth: 1'; \
	  echo; \
	  for i in $(notdir $(mandocrst)); do \
	    echo "   $$i"; \
	  done | LC_ALL=C sort; \
	} > $@

doc/man-%.rst: man/%.gen Makefile $(REPLACE_VARS_SED) | $(built_base_sources)
if MANPAGES_IN_DOC
	{ echo '.. This file is automatically updated at build time from $<.'; \
	  echo '.. Do not edit.'; \
	  echo; \
	  echo "$*"; \
	  echo '=========================================='; \
	  tail -n +3 $< | sed -f $(REPLACE_VARS_SED); \
	} > $@
else
	echo 'Man pages in documentation were disabled at configure time' >&2; \
	exit 1;
endif

doc/users/%: doc/users/%.in Makefile $(REPLACE_VARS_SED)
	cat $< | sed -f $(REPLACE_VARS_SED) | LC_ALL=C sort | uniq | (grep -v '^root' || true) > $@

userspecs = \
	doc/users/users \
	doc/users/groups \
	doc/users/groupmemberships

noinst_DATA = \
	$(BUILT_EXAMPLES) \
	doc/examples/bash_completion \
	doc/examples/bash_completion-debug \
	$(userspecs) \
	$(manhtml)

if HAS_SPHINX
if MANPAGES_IN_DOC
noinst_DATA += doc/man-html
else
noinst_DATA += doc/html
endif
endif

gnt_scripts = \
	scripts/gnt-backup \
	scripts/gnt-cluster \
	scripts/gnt-debug \
	scripts/gnt-group \
	scripts/gnt-instance \
	scripts/gnt-job \
	scripts/gnt-network \
	scripts/gnt-node \
	scripts/gnt-os \
	scripts/gnt-storage \
	scripts/gnt-filter

gnt_scripts_basenames = \
	$(patsubst scripts/%,%,$(patsubst daemons/%,%,$(gnt_scripts) $(gnt_python_sbin_SCRIPTS)))

gnt_python_sbin_SCRIPTS = \
	$(PYTHON_BOOTSTRAP_SBIN)

gntpython_SCRIPTS = $(gnt_scripts)

PYTHON_BOOTSTRAP_SBIN = \
	daemons/alcor-noded \
	daemons/alcor-rapi \
	daemons/alcor-watcher

PYTHON_BOOTSTRAP = \
	tools/burnin \
	tools/ensure-dirs \
	tools/node-cleanup \
	tools/node-daemon-setup \
	tools/prepare-node-join \
	tools/ssh-update \
	tools/ssl-update

qa_scripts = \
	qa/__init__.py \
	qa/alcor-qa.py \
	qa/qa_cluster.py \
	qa/qa_config.py \
	qa/qa_daemon.py \
	qa/qa_env.py \
	qa/qa_error.py \
	qa/qa_filters.py \
	qa/qa_group.py \
	qa/qa_instance.py \
	qa/qa_instance_utils.py \
	qa/qa_iptables.py \
	qa/qa_job.py \
	qa/qa_job_utils.py \
	qa/qa_logging.py \
	qa/qa_monitoring.py \
	qa/qa_network.py \
	qa/qa_node.py \
	qa/qa_os.py \
	qa/qa_performance.py \
	qa/qa_rapi.py \
	qa/qa_tags.py \
	qa/qa_utils.py \
	qa/colors.py

bin_SCRIPTS = $(HS_BIN_PROGS)
install-exec-hook:
	@mkdir_p@ $(DESTDIR)$(iallocatorsdir)
	$(LN_S) -f ../../../bin/htools \
	  $(DESTDIR)$(iallocatorsdir)/hail
	for role in $(HS_BIN_ROLES); do \
	  $(LN_S) -f htools $(DESTDIR)$(bindir)/$$role ; \
	done

HS_SRCS = $(HS_LIBTESTBUILT_SRCS)

HS_MAKEFILE_GHC_SRCS = $(HS_SRC_PROGS:%=%.hs)
if WANT_HSTESTS
HS_MAKEFILE_GHC_SRCS += $(HS_TEST_PROGS:%=%.hs)
endif
Makefile.ghc: $(HS_MAKEFILE_GHC_SRCS) Makefile $(HASKELL_PACKAGE_VERSIONS_FILE) \
              | $(built_base_sources) $(HS_BUILT_SRCS)
	$(GHC) -M -dep-makefile $@ $(DEP_SUFFIXES) $(HFLAGS) $(HFLAGS_DYNAMIC) \
		-itest/hs \
		$(HEXTRA_COMBINED) $(HS_MAKEFILE_GHC_SRCS)
	sed -i -r -e 's/([^ ]+)\.hi$$/\1.hi \1.o/' -e 's/([^ ]+)_hi$$/\1_hi \1_o/' $@

@include_makefile_ghc@

HASKELL_PACKAGE_IDS_FILE = alcor.depsflags

HASKELL_PACKAGE_VERSIONS_FILE = cabal_macros.h

$(HASKELL_PACKAGE_VERSIONS_FILE): Makefile alcor.cabal \
                                  cabal/CabalDependenciesMacros.hs
	touch empty-cabal-config
	$(CABAL) --config-file=empty-cabal-config \
	  $(CABAL_CONFIGURE_CMD) --user \
	  -f`test $(HTEST) == yes && echo "htest" || echo "-htest"` \
	  -f`test $(ENABLE_MOND) == True && echo "mond" || echo "-mond"` \
	  -f`test $(ENABLE_METADATA) == True && echo "metad" || echo "-metad"` \
	  -f`test $(ENABLE_NETWORK_BSD) == True && echo "network_bsd" || echo "-network_bsd"`
	runhaskell $(abs_top_srcdir)/cabal/CabalDependenciesMacros.hs \
	  alcor.cabal \
	  $(HASKELL_PACKAGE_IDS_FILE) \
	  $(HASKELL_PACKAGE_VERSIONS_FILE)

test/hs/%.o: $(HASKELL_PACKAGE_VERSIONS_FILE)
	@echo '[GHC|test]: $@ <- test/hs/$^'
	@set -o pipefail ; \
	$(GHC) -c $(HFLAGS) -itest/hs $(HFLAGS_DYNAMIC) \
		$(HEXTRA_COMBINED) $(HEXTRA_TEST) $(@:%.o=%.hs) | \
		sed '/^Loading package /d'

%.o: $(HASKELL_PACKAGE_VERSIONS_FILE)
	@echo '[GHC]: $@ <- $^'
	@set -o pipefail ; \
	$(GHC) -c $(HFLAGS) $(HFLAGS_DYNAMIC) \
		$(HEXTRA_COMBINED) $(@:%.o=%.hs) | \
		sed '/^Loading package /d'

if HPROFILE
%.$(HPROF_SUFFIX)_o: %.o
	@echo '[GHC|prof]: $@ <- $^'
	@set -o pipefail ; \
	$(GHC) -c $(HFLAGS) \
	  $(HPROFFLAGS) \
		$(HEXTRA_COMBINED) \
		$(@:%.$(HPROF_SUFFIX)_o=%.hs) | \
		sed '/^Loading package /d'
endif

%.$(HTEST_SUFFIX)_o: %.o
	@echo '[GHC|test]: $@ <- $^'
	@set -o pipefail ; \
	$(GHC) -c $(HTEST_FLAGS) \
		$(HEXTRA_COMBINED) $(HEXTRA_TEST) $(@:%.$(HTEST_SUFFIX)_o=%.hs) | \
		sed '/^Loading package /d'

%.hi: %.o ;
%.$(HTEST_SUFFIX)_hi: %.$(HTEST_SUFFIX)_o ;
%.$(HPROF_SUFFIX)_hi: %.$(HPROF_SUFFIX)_o ;

if HPROFILE
$(HS_SRC_PROGS): %: %.$(HPROF_SUFFIX)_o | stamp-directories
	@echo '[GHC-link]: $@'
	$(GHC) $(HFLAGS) $(HPROFFLAGS) \
		$(HEXTRA_COMBINED) --make $(@:%=%.hs)
else
$(HS_SRC_PROGS): %: %.o | stamp-directories
	@echo '[GHC-link]: $@'
	$(GHC) $(HFLAGS) $(HFLAGS_DYNAMIC) \
		$(HEXTRA_COMBINED) --make $(@:%=%.hs)
endif
	@rm -f $(notdir $@).tix
	@touch "$@"

$(HS_TEST_PROGS): %: %.$(HTEST_SUFFIX)_o \
			   | stamp-directories $(built_python_sources)
	@if [ "$(HS_NODEV)" ]; then \
	  echo "Error: cannot run unittests without the development" \
	       " libraries (see devnotes.rst)" 1>&2; \
	  exit 1; \
	fi
	@echo '[GHC-link|test]: $@'
	$(GHC) $(HTEST_FLAGS) \
		$(HEXTRA_COMBINED) $(HEXTRA_TEST) --make $(@:%=%.hs)
	@rm -f $(notdir $@).tix
	@touch "$@"

dist_sbin_SCRIPTS = \
	tools/alcor-listrunner

nodist_sbin_SCRIPTS = \
	daemons/alcor-cleaner \
	src/alcor-kvmd \
	src/alcor-luxid \
	src/alcor-confd \
	src/alcor-wconfd

src/alcor-luxid: src/hluxid
	cp -pf $< $@

all_sbin_scripts = \
	$(patsubst tools/%,%,$(patsubst daemons/%,%,$(patsubst scripts/%,%,\
	$(patsubst src/%,%,$(dist_sbin_SCRIPTS) $(nodist_sbin_SCRIPTS)))))

src/alcor-confd: src/hconfd
	cp -pf $< $@

if ENABLE_MOND
nodist_sbin_SCRIPTS += src/alcor-mond
endif

if ENABLE_METADATA
nodist_sbin_SCRIPTS += src/alcor-metad
endif

python_scripts = \
	tools/cfgshell \
	tools/cfgupgrade \
	tools/cfgupgrade12 \
	tools/cluster-merge \
	tools/confd-client \
	tools/fmtjson \
	tools/lvmstrap \
	tools/move-instance \
	tools/ovfconverter \
	tools/post-upgrade \
	tools/sanitize-config \
	tools/query-config

python_scripts_shebang = \
	$(patsubst tools/%,tools/shebang/%, $(python_scripts))

tools/shebang/%: tools/%
	mkdir -p tools/shebang
	head -1 $< | sed 's|#!/usr/bin/python3|#!$(PYTHON)|' > $@
	echo '# Generated file; do not edit.' >> $@
	tail -n +2 $< >> $@

dist_tools_SCRIPTS = \
	tools/kvm-console-wrapper \
	tools/master-ip-setup \
	tools/xen-console-wrapper

dist_tools_python_SCRIPTS = \
	tools/burnin

nodist_tools_python_SCRIPTS = \
	tools/node-cleanup \
	$(python_scripts_shebang)

tools_python_basenames = \
	$(patsubst shebang/%,%,\
	$(patsubst tools/%,%,\
	$(dist_tools_python_SCRIPTS) $(nodist_tools_python_SCRIPTS)))

nodist_tools_SCRIPTS = \
	tools/users-setup \
	tools/vcluster-setup

tools_basenames = $(patsubst tools/%,%,$(nodist_tools_SCRIPTS) $(dist_tools_SCRIPTS))

pkglib_python_scripts = \
	daemons/import-export \
	tools/check-cert-expired

nodist_pkglib_python_scripts = \
	tools/ensure-dirs \
	tools/node-daemon-setup \
	tools/prepare-node-join \
	tools/ssh-update \
	tools/ssl-update

pkglib_python_basenames = \
	$(patsubst daemons/%,%,$(patsubst tools/%,%,\
	$(pkglib_python_scripts) $(nodist_pkglib_python_scripts)))

myexeclib_SCRIPTS = \
	daemons/daemon-util \
	tools/kvm-ifup \
	tools/kvm-ifup-os \
	tools/xen-ifup-os \
	tools/vif-alcor \
	tools/vif-alcor-metad \
	tools/net-common \
	$(HS_MYEXECLIB_PROGS)

myexeclib_scripts_basenames = \
	$(patsubst tools/%,%,$(patsubst daemons/%,%,$(patsubst src/%,%,$(myexeclib_SCRIPTS))))

EXTRA_DIST += \
	NEWS \
	UPGRADE \
	pydoctor.ini \
	pylintrc \
	pylintrc-test \
	autotools/build-bash-completion \
	autotools/build-rpc \
	autotools/check-header \
	autotools/check-imports \
	autotools/check-man-dashes \
	autotools/check-man-references \
	autotools/check-man-warnings \
	autotools/check-news \
	autotools/check-python-code \
	autotools/check-tar \
	autotools/check-version \
	autotools/docpp \
	autotools/gen-py-coverage \
	autotools/print-py-constants \
	autotools/sphinx-wrapper \
	autotools/testrunner \
	autotools/wrong-hardcoded-paths \
	cabal/cabal-from-modules.py \
	$(RUN_IN_TEMPDIR) \
	daemons/daemon-util.in \
	daemons/alcor-cleaner.in \
	$(pkglib_python_scripts) \
	devel/build_chroot \
	devel/upload \
	devel/webserver \
	tools/kvm-ifup.in \
	tools/ifup-os.in \
	tools/vif-alcor.in \
	tools/vif-alcor-metad.in \
	tools/net-common.in \
	tools/vcluster-setup.in \
	$(python_scripts) \
	$(docinput) \
	doc/html \
	$(BUILT_EXAMPLES:%=%.in) \
	doc/examples/alcor.default \
	doc/examples/alcor.default-debug \
	doc/examples/hooks/ethers \
	doc/examples/gnt-debug/README \
	doc/examples/gnt-debug/delay0.json \
	doc/examples/gnt-debug/delay50.json \
	doc/examples/systemd/alcor-master.target \
	doc/examples/systemd/alcor-node.target \
	doc/examples/systemd/alcor.service \
	doc/examples/systemd/alcor.target \
	doc/users/groupmemberships.in \
	doc/users/groups.in \
	doc/users/users.in \
	alcor.cabal \
	cabal/alcor.template.cabal \
	cabal/CabalDependenciesMacros.hs \
	$(dist_TESTS) \
	$(TEST_FILES) \
	$(python_test_support) \
	$(python_test_utils) \
	man/footer.rst \
	$(manrst) \
	qa/qa-sample.json \
	$(qa_scripts) \
	$(HS_LIBTEST_SRCS) $(HS_BUILT_SRCS_IN) \
	$(HS_PROG_SRCS) \
	src/lint-hints.hs \
	test/hs/cli-tests-defs.sh \
	test/hs/offline-test.sh \
	.ghci

man_MANS = \
	man/alcor-cleaner.8 \
	man/alcor-confd.8 \
	man/alcor-luxid.8 \
	man/alcor-listrunner.8 \
	man/alcor-kvmd.8 \
	man/alcor-mond.8 \
	man/alcor-noded.8 \
	man/alcor-os-interface.7 \
	man/alcor-extstorage-interface.7 \
	man/alcor-rapi.8 \
	man/alcor-watcher.8 \
	man/alcor-wconfd.8 \
	man/alcor.7 \
	man/gnt-backup.8 \
	man/gnt-cluster.8 \
	man/gnt-debug.8 \
	man/gnt-group.8 \
	man/gnt-network.8 \
	man/gnt-instance.8 \
	man/gnt-job.8 \
	man/gnt-node.8 \
	man/gnt-os.8 \
	man/gnt-storage.8 \
	man/gnt-filter.8 \
	man/hail.1 \
	man/harep.1 \
	man/hbal.1 \
	man/hcheck.1 \
	man/hinfo.1 \
	man/hscan.1 \
	man/hspace.1 \
	man/hsqueeze.1 \
	man/hroller.1 \
	man/htools.1 \
	man/mon-collector.7

mannoext = $(patsubst %.1,%,$(patsubst %.7,%,$(patsubst %.8,%,$(man_MANS))))

manrst = $(patsubst %,%.rst,$(mannoext))
manhtml = $(patsubst %.rst,%.html,$(manrst))
mangen = $(patsubst %.rst,%.gen,$(manrst))

manfullpath = $(patsubst man/%.1,man1/%.1,\
	$(patsubst man/%.7,man7/%.7,\
	$(patsubst man/%.8,man8/%.8,$(man_MANS))))

TEST_FILES = \
	test/autotools/autotools-check-news.test \
	test/data/htools/clean-nonzero-score.data \
	test/data/htools/common-suffix.data \
	test/data/htools/empty-cluster.data \
	test/data/htools/hail-alloc-dedicated-1.json \
	test/data/htools/hail-alloc-desired-location.json \
	test/data/htools/hail-alloc-drbd.json \
	test/data/htools/hail-alloc-drbd-restricted.json \
	test/data/htools/hail-alloc-ext.json \
	test/data/htools/hail-alloc-invalid-network.json \
	test/data/htools/hail-alloc-invalid-twodisks.json \
	test/data/htools/hail-alloc-restricted-network.json \
	test/data/htools/hail-alloc-nlocation.json \
	test/data/htools/hail-alloc-plain-tags.json \
	test/data/htools/hail-alloc-secondary.json \
	test/data/htools/hail-alloc-spindles.json \
	test/data/htools/hail-alloc-twodisks.json \
	test/data/htools/hail-change-group.json \
	test/data/htools/hail-invalid-reloc.json \
	test/data/htools/hail-node-evac.json \
	test/data/htools/hail-reloc-drbd.json \
	test/data/htools/hail-reloc-drbd-crowded.json \
	test/data/htools/hbal-cpu-speed.data \
	test/data/htools/hbal-desiredlocation-1.data \
	test/data/htools/hbal-desiredlocation-2.data \
	test/data/htools/hbal-desiredlocation-3.data \
	test/data/htools/hbal-desiredlocation-4.data \
	test/data/htools/hbal-dyn.data \
	test/data/htools/hbal-evac.data \
	test/data/htools/hbal-excl-tags.data \
	test/data/htools/hbal-forth.data \
	test/data/htools/hbal-location-1.data \
	test/data/htools/hbal-location-exclusion.data \
	test/data/htools/hbal-location-2.data \
	test/data/htools/hbal-migration-1.data \
	test/data/htools/hbal-migration-2.data \
	test/data/htools/hbal-migration-3.data \
	test/data/htools/hail-multialloc-dedicated.json \
	test/data/htools/hbal-soft-errors.data \
	test/data/htools/hbal-soft-errors2.data \
	test/data/htools/hbal-split-insts.data \
	test/data/htools/hspace-bad-group.data \
	test/data/htools/hspace-existing.data \
	test/data/htools/hspace-groups-one.data \
	test/data/htools/hspace-groups-two.data \
	test/data/htools/hspace-tiered-dualspec-exclusive.data \
	test/data/htools/hspace-tiered-dualspec.data \
	test/data/htools/hspace-tiered-exclusive.data \
	test/data/htools/hspace-tiered-ipolicy.data \
	test/data/htools/hspace-tiered-mixed.data \
	test/data/htools/hspace-tiered-resourcetypes.data \
	test/data/htools/hspace-tiered-vcpu.data \
	test/data/htools/hspace-tiered.data \
	test/data/htools/invalid-node.data \
	test/data/htools/missing-resources.data \
	test/data/htools/multiple-master.data \
	test/data/htools/multiple-tags.data \
	test/data/htools/n1-failure.data \
	test/data/htools/partly-used.data \
	test/data/htools/rapi/groups.json \
	test/data/htools/rapi/info.json \
	test/data/htools/rapi/instances.json \
	test/data/htools/rapi/nodes.json \
	test/data/htools/hroller-full.data \
	test/data/htools/hroller-nodegroups.data \
	test/data/htools/hroller-nonredundant.data \
	test/data/htools/hroller-online.data \
	test/data/htools/hsqueeze-mixed-instances.data \
	test/data/htools/hsqueeze-overutilized.data \
	test/data/htools/hsqueeze-underutilized.data \
	test/data/htools/plain-n1-restriction.data \
	test/data/htools/shared-n1-failure.data \
	test/data/htools/shared-n1-restriction.data \
	test/data/htools/unique-reboot-order.data \
	test/data/mond-data.txt \
	test/hs/shelltests/htools-balancing.test \
	test/hs/shelltests/htools-basic.test \
	test/hs/shelltests/htools-dynutil.test \
	test/hs/shelltests/htools-excl.test \
	test/hs/shelltests/htools-hail.test \
	test/hs/shelltests/htools-hbal-evac.test \
	test/hs/shelltests/htools-hbal.test \
	test/hs/shelltests/htools-hcheck.test \
	test/hs/shelltests/htools-hroller.test \
	test/hs/shelltests/htools-hspace.test \
	test/hs/shelltests/htools-hsqueeze.test \
	test/hs/shelltests/htools-invalid.test \
	test/hs/shelltests/htools-multi-group.test \
	test/hs/shelltests/htools-no-backend.test \
	test/hs/shelltests/htools-rapi.test \
	test/hs/shelltests/htools-single-group.test \
	test/hs/shelltests/htools-text-backend.test \
	test/hs/shelltests/htools-mon-collector.test \
	test/data/bdev-drbd-8.0.txt \
	test/data/bdev-drbd-8.3.txt \
	test/data/bdev-drbd-8.4.txt \
	test/data/bdev-drbd-8.4-no-disk-params.txt \
	test/data/bdev-drbd-disk.txt \
	test/data/bdev-drbd-net-ip4.txt \
	test/data/bdev-drbd-net-ip6.txt \
	test/data/bdev-rbd/json_output_empty.txt \
	test/data/bdev-rbd/json_output_extra_matches.txt \
	test/data/bdev-rbd/json_output_no_matches.txt \
	test/data/bdev-rbd/json_output_ok.txt \
	test/data/bdev-rbd/plain_output_new_extra_matches.txt \
	test/data/bdev-rbd/plain_output_new_no_matches.txt \
	test/data/bdev-rbd/plain_output_new_ok.txt \
	test/data/bdev-rbd/plain_output_old_empty.txt \
	test/data/bdev-rbd/plain_output_old_extra_matches.txt \
	test/data/bdev-rbd/plain_output_old_no_matches.txt \
	test/data/bdev-rbd/plain_output_old_ok.txt \
	test/data/bdev-rbd/output_invalid.txt \
	test/data/cert1.pem \
	test/data/cert2.pem \
	test/data/cgroup_root/memory/lxc/instance1/memory.limit_in_bytes \
	test/data/cgroup_root/cpuset/some_group/lxc/instance1/cpuset.cpus \
	test/data/cgroup_root/devices/some_group/lxc/instance1/devices.list \
	test/data/cluster_config_2.7.json \
	test/data/cluster_config_2.8.json \
	test/data/cluster_config_2.9.json \
	test/data/cluster_config_2.10.json \
	test/data/cluster_config_2.11.json \
	test/data/cluster_config_2.12.json \
	test/data/cluster_config_2.13.json \
	test/data/cluster_config_2.14.json \
	test/data/cluster_config_2.15.json \
	test/data/cluster_config_2.16.json \
	test/data/cluster_config_3.0.json \
	test/data/instance-minor-pairing.txt \
	test/data/instance-disks.txt \
	test/data/ip-addr-show-dummy0.txt \
	test/data/ip-addr-show-lo-ipv4.txt \
	test/data/ip-addr-show-lo-ipv6.txt \
	test/data/ip-addr-show-lo-oneline-ipv4.txt \
	test/data/ip-addr-show-lo-oneline-ipv6.txt \
	test/data/ip-addr-show-lo-oneline.txt \
	test/data/ip-addr-show-lo.txt \
	test/data/kvm_0.12.5_help.txt \
	test/data/kvm_0.15.90_help.txt \
	test/data/kvm_0.9.1_help.txt \
	test/data/kvm_0.9.1_help_boot_test.txt \
	test/data/kvm_1.0_help.txt \
	test/data/kvm_1.1.2_help.txt \
	test/data/kvm_5.2.0_help.txt \
	test/data/kvm_current_help.txt \
	test/data/kvm_6.0.0_machine.txt \
	test/data/kvm_runtime.json \
	test/data/lvs_lv.txt \
	test/data/NEWS_OK.txt \
	test/data/NEWS_previous_unreleased.txt \
	test/data/ovfdata/compr_disk.vmdk.gz \
	test/data/ovfdata/config.ini \
	test/data/ovfdata/corrupted_resources.ovf \
	test/data/ovfdata/empty.ini \
	test/data/ovfdata/empty.ovf \
	test/data/ovfdata/alcor.mf \
	test/data/ovfdata/alcor.ovf \
	test/data/ovfdata/gzip_disk.ovf \
	test/data/ovfdata/new_disk.vmdk \
	test/data/ovfdata/no_disk.ini \
	test/data/ovfdata/no_disk_in_ref.ovf \
	test/data/ovfdata/no_os.ini \
	test/data/ovfdata/no_ovf.ova \
	test/data/ovfdata/other/rawdisk.raw \
	test/data/ovfdata/ova.ova \
	test/data/ovfdata/rawdisk.raw \
	test/data/ovfdata/second_disk.vmdk \
	test/data/ovfdata/unsafe_path.ini \
	test/data/ovfdata/virtualbox.ovf \
	test/data/ovfdata/wrong_config.ini \
	test/data/ovfdata/wrong_extension.ovd \
	test/data/ovfdata/wrong_manifest.mf \
	test/data/ovfdata/wrong_manifest.ovf \
	test/data/ovfdata/wrong_ova.ova \
	test/data/ovfdata/wrong_xml.ovf \
	test/data/proc_cgroup.txt \
	test/data/proc_diskstats.txt \
	test/data/proc_drbd8.txt \
	test/data/proc_drbd80-emptyline.txt \
	test/data/proc_drbd80-emptyversion.txt \
	test/data/proc_drbd83.txt \
	test/data/proc_drbd83_sync.txt \
	test/data/proc_drbd83_sync_want.txt \
	test/data/proc_drbd83_sync_krnl2.6.39.txt \
	test/data/proc_drbd84.txt \
	test/data/proc_drbd84_emptyfirst.txt \
	test/data/proc_drbd84_sync.txt \
	test/data/proc_meminfo.txt \
	test/data/proc_cpuinfo.txt \
	test/data/qa-minimal-nodes-instances-only.json \
	test/data/sys_drbd_usermode_helper.txt \
	test/data/vgreduce-removemissing-2.02.02.txt \
	test/data/vgreduce-removemissing-2.02.66-fail.txt \
	test/data/vgreduce-removemissing-2.02.66-ok.txt \
	test/data/vgs-missing-pvs-2.02.02.txt \
	test/data/vgs-missing-pvs-2.02.66.txt \
	test/data/xen-xl-list-4.4-crashed-instances.txt \
	test/data/xen-xl-info-4.0.1.txt \
	test/data/xen-xl-list-4.0.1-dom0-only.txt \
	test/data/xen-xl-list-4.0.1-four-instances.txt \
	test/data/xen-xl-list-long-4.0.1.txt \
	test/data/xen-xl-uptime-4.0.1.txt \
	test/py/alcor-cli.test \
	test/py/gnt-cli.test \
	test/py/import-export_unittest-helper


python_tests = \
	doc/examples/rapi_testutils.py \
	test/py/cmdlib/backup_unittest.py \
	test/py/cmdlib/cluster_unittest.py \
	test/py/cmdlib/cmdlib_unittest.py \
	test/py/cmdlib/group_unittest.py \
	test/py/cmdlib/instance_unittest.py \
	test/py/cmdlib/instance_migration_unittest.py \
	test/py/cmdlib/instance_query_unittest.py \
	test/py/cmdlib/instance_storage_unittest.py \
	test/py/cmdlib/node_unittest.py \
	test/py/cmdlib/test_unittest.py \
	test/py/cfgupgrade_unittest.py \
	test/py/docs_unittest.py \
	test/py/alcor.asyncnotifier_unittest.py \
	test/py/alcor.backend_unittest-runasroot.py \
	test/py/alcor.backend_unittest.py \
	test/py/alcor.bootstrap_unittest.py \
	test/py/alcor.cli_unittest.py \
	test/py/alcor.cli_opts_unittest.py \
	test/py/alcor.client.gnt_cluster_unittest.py \
	test/py/alcor.client.gnt_instance_unittest.py \
	test/py/alcor.client.gnt_job_unittest.py \
	test/py/alcor.compat_unittest.py \
	test/py/alcor.confd.client_unittest.py \
	test/py/alcor.config_unittest.py \
	test/py/alcor.constants_unittest.py \
	test/py/alcor.daemon_unittest.py \
	test/py/alcor.errors_unittest.py \
	test/py/alcor.hooks_unittest.py \
	test/py/alcor.ht_unittest.py \
	test/py/alcor.http_unittest.py \
	test/py/alcor.hypervisor.hv_chroot_unittest.py \
	test/py/alcor.hypervisor.hv_fake_unittest.py \
	test/py/alcor.hypervisor.hv_kvm_unittest.py \
	test/py/alcor.hypervisor.hv_lxc_unittest.py \
	test/py/alcor.hypervisor.hv_xen_unittest.py \
	test/py/alcor.hypervisor_unittest.py \
	test/py/alcor.impexpd_unittest.py \
	test/py/alcor.jqueue_unittest.py \
	test/py/alcor.jstore_unittest.py \
	test/py/alcor.locking_unittest.py \
	test/py/alcor.luxi_unittest.py \
	test/py/alcor.masterd.iallocator_unittest.py \
	test/py/alcor.masterd.instance_unittest.py \
	test/py/alcor.mcpu_unittest.py \
	test/py/alcor.netutils_unittest.py \
	test/py/alcor.objects_unittest.py \
	test/py/alcor.opcodes_unittest.py \
	test/py/alcor.outils_unittest.py \
	test/py/alcor.ovf_unittest.py \
	test/py/alcor.qlang_unittest.py \
	test/py/alcor.query_unittest.py \
	test/py/alcor.rapi.baserlib_unittest.py \
	test/py/alcor.rapi.client_unittest.py \
	test/py/alcor.rapi.resources_unittest.py \
	test/py/alcor.rapi.rlib2_unittest.py \
	test/py/alcor.rapi.testutils_unittest.py \
	test/py/alcor.rpc_unittest.py \
	test/py/alcor.rpc.client_unittest.py \
	test/py/alcor.runtime_unittest.py \
	test/py/alcor.serializer_unittest.py \
	test/py/alcor.server.rapi_unittest.py \
	test/py/alcor.ssconf_unittest.py \
	test/py/alcor.ssh_unittest.py \
	test/py/alcor.storage.bdev_unittest.py \
	test/py/alcor.storage.container_unittest.py \
	test/py/alcor.storage.drbd_unittest.py \
	test/py/alcor.storage.filestorage_unittest.py \
	test/py/alcor.storage.gluster_unittest.py \
	test/py/alcor.tools.burnin_unittest.py \
	test/py/alcor.tools.ensure_dirs_unittest.py \
	test/py/alcor.tools.node_daemon_setup_unittest.py \
	test/py/alcor.tools.prepare_node_join_unittest.py \
	test/py/alcor.uidpool_unittest.py \
	test/py/alcor.utils.algo_unittest.py \
	test/py/alcor.utils.filelock_unittest.py \
	test/py/alcor.utils.hash_unittest.py \
	test/py/alcor.utils.io_unittest-runasroot.py \
	test/py/alcor.utils.io_unittest.py \
	test/py/alcor.utils.log_unittest.py \
	test/py/alcor.utils.livelock_unittest.py \
	test/py/alcor.utils.lvm_unittest.py \
	test/py/alcor.utils.mlock_unittest.py \
	test/py/alcor.utils.nodesetup_unittest.py \
	test/py/alcor.utils.process_unittest.py \
	test/py/alcor.utils.retry_unittest.py \
	test/py/alcor.utils.security_unittest.py \
	test/py/alcor.utils.storage_unittest.py \
	test/py/alcor.utils.text_unittest.py \
	test/py/alcor.utils.version_unittest.py \
	test/py/alcor.utils.wrapper_unittest.py \
	test/py/alcor.utils.x509_unittest.py \
	test/py/alcor.utils.bitarrays_unittest.py \
	test/py/alcor.utils_unittest.py \
	test/py/alcor.vcluster_unittest.py \
	test/py/alcor.workerpool_unittest.py \
	test/py/pycurl_reset_unittest.py \
	test/py/qa.qa_config_unittest.py \
	test/py/tempfile_fork_unittest.py

python_test_support = \
	test/py/__init__.py \
	test/py/lockperf.py \
	test/py/testutils_ssh.py \
	test/py/mocks.py \
	test/py/testutils/__init__.py \
	test/py/testutils/config_mock.py \
	test/py/cmdlib/__init__.py \
	test/py/cmdlib/testsupport/__init__.py \
	test/py/cmdlib/testsupport/cmdlib_testcase.py \
	test/py/cmdlib/testsupport/iallocator_mock.py \
	test/py/cmdlib/testsupport/livelock_mock.py \
	test/py/cmdlib/testsupport/netutils_mock.py \
	test/py/cmdlib/testsupport/pathutils_mock.py \
	test/py/cmdlib/testsupport/processor_mock.py \
	test/py/cmdlib/testsupport/rpc_runner_mock.py \
	test/py/cmdlib/testsupport/ssh_mock.py \
	test/py/cmdlib/testsupport/utils_mock.py \
	test/py/cmdlib/testsupport/util.py \
	test/py/cmdlib/testsupport/wconfd_mock.py

haskell_tests = test/hs/htest

dist_TESTS = \
	test/py/check-cert-expired_unittest.bash \
	test/py/daemon-util_unittest.bash \
	test/py/systemd_unittest.bash \
	test/py/alcor-cleaner_unittest.bash \
	test/py/import-export_unittest.bash \
	test/py/cli-test.bash \
	test/py/bash_completion.bash

if PY_UNIT
dist_TESTS += $(python_tests)
endif

nodist_TESTS =
check_SCRIPTS =

if WANT_HSTESTS
nodist_TESTS += $(haskell_tests)
test/hs/offline-test.sh: test/hs/hpc-htools test/hs/hpc-mon-collector
dist_TESTS += test/hs/offline-test.sh
check_SCRIPTS += \
	test/hs/hpc-htools \
	test/hs/hpc-mon-collector \
	$(HS_BUILT_TEST_HELPERS)
endif

TESTS = $(dist_TESTS) $(nodist_TESTS)

PLAIN_TESTS_ENVIRONMENT = \
	PYTHONPATH=.:./test/py \
	TOP_SRCDIR=$(abs_top_srcdir) TOP_BUILDDIR=$(abs_top_builddir) \
	PYTHON=$(PYTHON) FAKEROOT=$(FAKEROOT_PATH) \
	$(RUN_IN_TEMPDIR)

TESTS_ENVIRONMENT = \
	$(PLAIN_TESTS_ENVIRONMENT) $(abs_top_srcdir)/autotools/testrunner

all_python_code = \
	$(dist_sbin_SCRIPTS) \
	$(python_scripts) \
	$(pkglib_python_scripts) \
	$(nodist_pkglib_python_scripts) \
	$(nodist_tools_python_scripts) \
	$(pkgpython_PYTHON) \
	$(client_PYTHON) \
	$(cmdlib_PYTHON) \
	$(cmdlib_cluster_PYTHON) \
	$(config_PYTHON) \
	$(hypervisor_PYTHON) \
	$(hypervisor_hv_kvm_PYTHON) \
	$(jqueue_PYTHON) \
	$(storage_PYTHON) \
	$(rapi_PYTHON) \
	$(server_PYTHON) \
	$(rpc_PYTHON) \
	$(rpc_stub_PYTHON) \
	$(pytools_PYTHON) \
	$(http_PYTHON) \
	$(confd_PYTHON) \
	$(masterd_PYTHON) \
	$(impexpd_PYTHON) \
	$(utils_PYTHON) \
	$(watcher_PYTHON) \
	$(noinst_PYTHON) \
	$(qa_scripts)

if PY_UNIT
all_python_code += $(python_tests)
all_python_code += $(python_test_support)
all_python_code += $(python_test_utils)
endif

srclink_files = \
	man/footer.rst \
	test/py/check-cert-expired_unittest.bash \
	test/py/daemon-util_unittest.bash \
	test/py/systemd_unittest.bash \
	test/py/alcor-cleaner_unittest.bash \
	test/py/import-export_unittest.bash \
	test/py/cli-test.bash \
	test/py/bash_completion.bash \
	test/hs/offline-test.sh \
	test/hs/cli-tests-defs.sh \
	$(all_python_code) \
	$(HS_LIBTEST_SRCS) $(HS_PROG_SRCS) \
	$(docinput)

check_python_code = \
	$(BUILD_BASH_COMPLETION) \
	$(CHECK_IMPORTS) \
	$(CHECK_HEADER) \
	$(DOCPP) \
	$(all_python_code)

lint_python_code = \
	alcor \
	alcor/http/server.py \
	$(dist_sbin_SCRIPTS) \
	$(python_scripts) \
	$(pkglib_python_scripts) \
	$(BUILD_BASH_COMPLETION) \
	$(CHECK_IMPORTS) \
	$(CHECK_HEADER) \
	$(DOCPP) \
	$(gnt_python_sbin_SCRIPTS) \
	$(PYTHON_BOOTSTRAP)

standalone_python_modules = \
	lib/rapi/client.py \
	tools/alcor-listrunner

pycodestyle_python_code = \
	alcor \
	alcor/http/server.py \
	$(dist_sbin_SCRIPTS) \
	$(python_scripts) \
	$(pkglib_python_scripts) \
	$(BUILD_BASH_COMPLETION) \
	$(CHECK_HEADER) \
	$(DOCPP) \
	$(PYTHON_BOOTSTRAP) \
	$(gnt_python_sbin_SCRIPTS) \
	qa \
	$(python_test_support)
	$(python_test_utils)

test/py/daemon-util_unittest.bash: daemons/daemon-util

test/py/systemd_unittest.bash: daemons/daemon-util $(BUILT_EXAMPLES)

test/py/alcor-cleaner_unittest.bash: daemons/alcor-cleaner

test/py/bash_completion.bash: doc/examples/bash_completion-debug

tools/kvm-ifup: tools/kvm-ifup.in $(REPLACE_VARS_SED)
	sed -f $(REPLACE_VARS_SED) < $< > $@
	chmod +x $@

tools/kvm-ifup-os: tools/ifup-os.in $(REPLACE_VARS_SED)
	sed -f $(REPLACE_VARS_SED) -e "s/ifup-os:/kvm-ifup-os:/" < $< > $@
	chmod +x $@

tools/xen-ifup-os: tools/ifup-os.in $(REPLACE_VARS_SED)
	sed -f $(REPLACE_VARS_SED) -e "s/ifup-os:/xen-ifup-os:/" < $< > $@
	chmod +x $@

tools/vif-alcor: tools/vif-alcor.in $(REPLACE_VARS_SED)
	sed -f $(REPLACE_VARS_SED) < $< > $@
	chmod +x $@

tools/vif-alcor-metad: tools/vif-alcor-metad.in $(REPLACE_VARS_SED)
	sed -f $(REPLACE_VARS_SED) < $< > $@
	chmod +x $@

tools/net-common: tools/net-common.in $(REPLACE_VARS_SED)
	sed -f $(REPLACE_VARS_SED) < $< > $@
	chmod +x $@

tools/users-setup: Makefile $(userspecs)
	set -e; \
	{ echo '#!/bin/sh'; \
	  echo 'if [ "x$$1" != "x--yes-do-it" ];'; \
	  echo 'then echo "This will do the following changes"'; \
	  $(AWK) -- '{print "echo + Will add group ",$$1; count++}\
		     END {if (count == 0) {print "echo + No groups to add"}}' doc/users/groups; \
	  $(AWK) -- '{if (NF > 1) {print "echo + Will add user",$$1,"with primary group",$$2} \
				  else {print "echo + Will add user",$$1}; count++}\
		     END {if (count == 0) {print "echo + No users to add"}}' doc/users/users; \
	  $(AWK) -- '{print "echo + Will add user",$$1,"to group",$$2}' doc/users/groupmemberships; \
	  echo 'echo'; \
	  echo 'echo "OK? (y/n)"'; \
	  echo 'read confirm'; \
	  echo 'if [ "x$$confirm" != "xy" ]; then exit 0; fi'; \
	  echo 'fi'; \
	  $(AWK) -- '{print "groupadd --system",$$1}' doc/users/groups; \
	  $(AWK) -- '{if (NF > 1) {print "useradd --system --gid",$$2,$$1} else {print "useradd --system",$$1}}' doc/users/users; \
	  $(AWK) -- '{print "usermod --append --groups",$$2,$$1}' doc/users/groupmemberships; \
	} > $@
	chmod +x $@

tools/vcluster-setup: tools/vcluster-setup.in $(REPLACE_VARS_SED)
	sed -f $(REPLACE_VARS_SED) < $< > $@
	chmod +x $@

daemons/%:: daemons/%.in $(REPLACE_VARS_SED)
	sed -f $(REPLACE_VARS_SED) < $< > $@
	chmod +x $@

doc/examples/%:: doc/examples/%.in $(REPLACE_VARS_SED)
	sed -f $(REPLACE_VARS_SED) < $< > $@

doc/examples/bash_completion: BC_ARGS = --compact
doc/examples/bash_completion-debug: BC_ARGS =

doc/examples/bash_completion doc/examples/bash_completion-debug: \
	$(BUILD_BASH_COMPLETION) $(RUN_IN_TEMPDIR) \
	lib/cli.py $(gnt_scripts) $(client_PYTHON) tools/burnin \
	daemons/alcor-cleaner \
	$(GENERATED_FILES) $(HS_GENERATED_FILES)
	PYTHONPATH=. $(RUN_IN_TEMPDIR) \
	  $(CURDIR)/$(BUILD_BASH_COMPLETION) $(BC_ARGS) > $@

man/%.gen: man/%.rst lib/query.py lib/build/sphinx_ext.py \
	lib/build/shell_example_lexer.py \
	| $(RUN_IN_TEMPDIR) $(built_python_sources)
	@echo "Checking $< for hardcoded paths..."
	@if grep -nEf autotools/wrong-hardcoded-paths $<; then \
	  echo "Man page $< has hardcoded paths (see above)!" 1>&2 ; \
	  exit 1; \
	fi
	set -e ; \
	trap 'echo auto-removing $@; rm $@' EXIT; \
	PYTHONPATH=. $(RUN_IN_TEMPDIR) $(CURDIR)/$(DOCPP) < $< | \
	  sed -f $(REPLACE_VARS_SED) > $@ ;\
	$(CHECK_MAN_REFERENCES) $@; \
	trap - EXIT

man/%.7 man/%.8 man/%.1: man/%.gen man/footer.rst
	@test -n "$(PANDOC)" || \
	  { echo 'pandoc' not found during configure; exit 1; }
	set -o pipefail -e; \
	trap 'echo auto-removing $@; rm $@' EXIT; \
	$(PANDOC) -s -f rst -t man $< man/footer.rst > $@; \
	if test -n "$(MAN_HAS_WARNINGS)"; then LC_ALL=$(UTF8_LOCALE) $(CHECK_MAN_WARNINGS) $@; fi; \
	$(CHECK_MAN_DASHES) $@; \
	trap - EXIT

man/%.html: man/%.gen man/footer.rst
	@test -n "$(PANDOC)" || \
	  { echo 'pandoc' not found during configure; exit 1; }
	set -o pipefail ; \
	$(PANDOC) --toc -s -f rst -t html $< man/footer.rst > $@

vcs-version:
	if test -d $(top_srcdir)/.git; then \
	  git -C $(top_srcdir) describe | tr '"' - > $@; \
	elif test ! -f $@ ; then \
	  echo "Cannot auto-generate $@ file"; exit 1; \
	fi

.PHONY: clean-vcs-version
clean-vcs-version:
	rm -f vcs-version

.PHONY: regen-vcs-version
regen-vcs-version:
	@set -e; \
	cd $(srcdir); \
	if test -d .git; then \
	  T=`mktemp` ; trap 'rm -f $$T' EXIT; \
	  git describe > $$T; \
	  if ! cmp --quiet $$T vcs-version; then \
	    mv $$T vcs-version; \
	  fi; \
	fi

src/Alcor/Version.hs: src/Alcor/Version.hs.in \
	vcs-version $(built_base_sources)
	set -e; \
	VCSVER=`cat $(srcdir)/vcs-version`; \
	sed -e 's"%ver%"'"$$VCSVER"'"' < $< > $@

src/Alcor/Hs2Py/ListConstants.hs: src/Alcor/Hs2Py/ListConstants.hs.in \
				   src/Alcor/Constants.hs \
				 | stamp-directories
	@echo Generating $@
	@set -e; \
	NAMES=$$(sed -e "/^--/ d" $(abs_top_srcdir)/src/Alcor/Constants.hs |\
		 sed -n -e "/=/ s/\(.*\) =.*/    '\1:/g p"); \
	m4 -DPY_CONSTANT_NAMES="$$NAMES" \
		$(abs_top_srcdir)/src/Alcor/Hs2Py/ListConstants.hs.in > $@

src/Alcor/Curl/Internal.hs: src/Alcor/Curl/Internal.hsc | stamp-directories
	hsc2hs -o $@ $<

test/hs/Test/Alcor/TestImports.hs: test/hs/Test/Alcor/TestImports.hs.in \
	$(built_base_sources)
	set -e; \
	{ cat $< ; \
	  echo ; \
	  for name in $(filter-out Alcor.THH,$(subst /,.,$(patsubst %.hs,%,$(patsubst src/%,%,$(HS_LIB_SRCS))))) ; do \
	    echo "import $$name ()" ; \
	  done ; \
	} > $@

lib/_constants.py: Makefile src/hs2py lib/_constants.py.in | stamp-directories
	cat $(abs_top_srcdir)/lib/_constants.py.in > $@
	src/hs2py --constants >> $@

lib/constants.py: lib/_constants.py

src/AutoConf.hs: Makefile src/AutoConf.hs.in $(PRINT_PY_CONSTANTS) \
	       | $(built_base_sources)
	@echo "m4 ... >" $@
	@m4 -DPACKAGE_VERSION="$(PACKAGE_VERSION)" \
	    -DVERSION_MAJOR="$(VERSION_MAJOR)" \
	    -DVERSION_MINOR="$(VERSION_MINOR)" \
	    -DVERSION_REVISION="$(VERSION_REVISION)" \
	    -DVERSION_SUFFIX="$(VERSION_SUFFIX)" \
	    -DVERSION_FULL="$(VERSION_FULL)" \
	    -DDIRVERSION="$(DIRVERSION)" \
	    -DLOCALSTATEDIR="$(localstatedir)" \
	    -DSYSCONFDIR="$(sysconfdir)" \
	    -DSSH_CONFIG_DIR="$(SSH_CONFIG_DIR)" \
	    -DSSH_LOGIN_USER="$(SSH_LOGIN_USER)" \
	    -DSSH_CONSOLE_USER="$(SSH_CONSOLE_USER)" \
	    -DEXPORT_DIR="$(EXPORT_DIR)" \
	    -DBACKUP_DIR="$(backup_dir)" \
	    -DOS_SEARCH_PATH="\"$(OS_SEARCH_PATH)\"" \
	    -DES_SEARCH_PATH="\"$(ES_SEARCH_PATH)\"" \
	    -DXEN_BOOTLOADER="$(XEN_BOOTLOADER)" \
	    -DXEN_CONFIG_DIR="$(XEN_CONFIG_DIR)" \
	    -DXEN_KERNEL="$(XEN_KERNEL)" \
	    -DXEN_INITRD="$(XEN_INITRD)" \
	    -DKVM_KERNEL="$(KVM_KERNEL)" \
	    -DSHARED_FILE_STORAGE_DIR="$(SHARED_FILE_STORAGE_DIR)" \
	    -DIALLOCATOR_SEARCH_PATH="\"$(IALLOCATOR_SEARCH_PATH)\"" \
	    -DDEFAULT_BRIDGE="$(DEFAULT_BRIDGE)" \
	    -DDEFAULT_VG="$(DEFAULT_VG)" \
	    -DKVM_PATH="$(KVM_PATH)" \
	    -DIP_PATH="$(IP_PATH)" \
	    -DSOCAT_PATH="$(SOCAT)" \
	    -DPYTHON_PATH="$(PYTHON)" \
	    -DSOCAT_USE_ESCAPE="$(SOCAT_USE_ESCAPE)" \
	    -DSOCAT_USE_COMPRESS="$(SOCAT_USE_COMPRESS)" \
	    -DLVM_STRIPECOUNT="$(LVM_STRIPECOUNT)" \
	    -DTOOLSDIR="$(libdir)/alcor/tools" \
	    -DGNT_SCRIPTS="$(foreach i,$(notdir $(gnt_scripts)),\"$(i)\":)" \
	    -DHS_HTOOLS_PROGS="$(foreach i,$(HS_HTOOLS_PROGS),\"$(i)\":)" \
	    -DPKGLIBDIR="$(libdir)/alcor" \
	    -DSHAREDIR="$(prefix)/share/alcor" \
	    -DVERSIONEDSHAREDIR="$(versionedsharedir)" \
	    -DDRBD_BARRIERS="$(DRBD_BARRIERS)" \
	    -DDRBD_NO_META_FLUSH="$(DRBD_NO_META_FLUSH)" \
	    -DSYSLOG_USAGE="$(SYSLOG_USAGE)" \
	    -DDAEMONS_GROUP="$(DAEMONS_GROUP)" \
	    -DADMIN_GROUP="$(ADMIN_GROUP)" \
	    -DMASTERD_USER="$(MASTERD_USER)" \
	    -DMASTERD_GROUP="$(MASTERD_GROUP)" \
	    -DMETAD_USER="$(METAD_USER)" \
	    -DMETAD_GROUP="$(METAD_GROUP)" \
	    -DRAPI_USER="$(RAPI_USER)" \
	    -DRAPI_GROUP="$(RAPI_GROUP)" \
	    -DCONFD_USER="$(CONFD_USER)" \
	    -DCONFD_GROUP="$(CONFD_GROUP)" \
	    -DWCONFD_USER="$(WCONFD_USER)" \
	    -DWCONFD_GROUP="$(WCONFD_GROUP)" \
	    -DKVMD_USER="$(KVMD_USER)" \
	    -DKVMD_GROUP="$(KVMD_GROUP)" \
	    -DLUXID_USER="$(LUXID_USER)" \
	    -DLUXID_GROUP="$(LUXID_GROUP)" \
	    -DNODED_USER="$(NODED_USER)" \
	    -DNODED_GROUP="$(NODED_GROUP)" \
	    -DMOND_USER="$(MOND_USER)" \
	    -DMOND_GROUP="$(MOND_GROUP)" \
	    -DMETAD_USER="$(METAD_USER)" \
	    -DMETAD_GROUP="$(METAD_GROUP)" \
	    -DDISK_SEPARATOR="$(DISK_SEPARATOR)" \
	    -DQEMUIMG_PATH="$(QEMUIMG_PATH)" \
	    -DENABLE_RESTRICTED_COMMANDS="$(ENABLE_RESTRICTED_COMMANDS)" \
	    -DENABLE_METADATA="$(ENABLE_METADATA)" \
	    -DENABLE_MOND="$(ENABLE_MOND)" \
	    -DHAS_GNU_LN="$(HAS_GNU_LN)" \
	    -DMAN_PAGES="$$(for i in $(notdir $(man_MANS)); do \
			    echo -n "$$i" | sed -re 's/^(.*)\.([0-9]+)$$/("\1",\2):/g'; \
			    done)" \
	    -DAF_INET4="$$(PYTHONPATH=. $(PYTHON) $(PRINT_PY_CONSTANTS) AF_INET4)" \
	    -DAF_INET6="$$(PYTHONPATH=. $(PYTHON) $(PRINT_PY_CONSTANTS) AF_INET6)" \
	$(abs_top_srcdir)/src/AutoConf.hs.in > $@

lib/_vcsversion.py: Makefile vcs-version | stamp-directories
	set -e; \
	VCSVER=`cat $(srcdir)/vcs-version`; \
	{ echo '# This file is automatically generated, do not edit!'; \
	  echo '#'; \
	  echo ''; \
	  echo '"""Build-time VCS version number for Alcor.'; \
	  echo '';\
	  echo 'This file is autogenerated by the build process.'; \
	  echo 'For any changes you need to re-run ./configure (and'; \
	  echo 'not edit by hand).'; \
	  echo ''; \
	  echo '"""'; \
	  echo ''; \
	  echo '# pylint: disable=C0301,C0324'; \
	  echo '# because this is autogenerated, we do not want'; \
	  echo '# style warnings' ; \
	  echo ''; \
	  echo "VCS_VERSION = '$$VCSVER'"; \
	} > $@

lib/opcodes.py: Makefile src/hs2py lib/opcodes.py.in_before \
		lib/opcodes.py.in_after | stamp-directories
	cat $(abs_top_srcdir)/lib/opcodes.py.in_before > $@
	src/hs2py --opcodes >> $@
	cat $(abs_top_srcdir)/lib/opcodes.py.in_after >> $@

lib/_generated_rpc.py: lib/rpc_defs.py $(BUILD_RPC) | $(built_base_sources) $(built_python_base_sources)
	PYTHONPATH=. $(RUN_IN_TEMPDIR) $(CURDIR)/$(BUILD_RPC) lib/rpc_defs.py > $@

if ENABLE_METADATA
lib/rpc/stub/metad.py: Makefile src/hs2py | stamp-directories
	src/hs2py --metad-rpc > $@
endif

lib/rpc/stub/wconfd.py: Makefile src/hs2py | stamp-directories
	src/hs2py --wconfd-rpc > $@

$(SHELL_ENV_INIT): Makefile stamp-directories
	set -e; \
	{ echo '# Allow overriding for tests'; \
	  echo 'readonly LOCALSTATEDIR=$${LOCALSTATEDIR:-$${GANETI_ROOTDIR:-}$(localstatedir)}'; \
	  echo 'readonly SYSCONFDIR=$${SYSCONFDIR:-$${GANETI_ROOTDIR:-}$(sysconfdir)}'; \
	  echo; \
	  echo 'readonly PKGLIBDIR=$(libdir)/alcor'; \
	  echo 'readonly LOG_DIR="$$LOCALSTATEDIR/log/alcor"'; \
	  echo 'readonly RUN_DIR="$$LOCALSTATEDIR/run/alcor"'; \
	  echo 'readonly DATA_DIR="$$LOCALSTATEDIR/lib/alcor"'; \
	  echo 'readonly CONF_DIR="$$SYSCONFDIR/alcor"'; \
	} > $@

$(REPLACE_VARS_SED): $(SHELL_ENV_INIT) Makefile stamp-directories
	set -e; \
	{ echo 's#@''PREFIX@#$(prefix)#g'; \
	  echo 's#@''SYSCONFDIR@#$(sysconfdir)#g'; \
	  echo 's#@''LOCALSTATEDIR@#$(localstatedir)#g'; \
	  echo 's#@''BINDIR@#$(BINDIR)#g'; \
	  echo 's#@''SBINDIR@#$(SBINDIR)#g'; \
	  echo 's#@''LIBDIR@#$(libdir)#g'; \
	  echo 's#@''GANETI_VERSION@#$(PACKAGE_VERSION)#g'; \
	  echo 's#@''CUSTOM_XEN_BOOTLOADER@#$(XEN_BOOTLOADER)#g'; \
	  echo 's#@''CUSTOM_XEN_KERNEL@#$(XEN_KERNEL)#g'; \
	  echo 's#@''CUSTOM_XEN_INITRD@#$(XEN_INITRD)#g'; \
	  echo 's#@''CUSTOM_IALLOCATOR_SEARCH_PATH@#$(IALLOCATOR_SEARCH_PATH)#g'; \
	  echo 's#@''CUSTOM_EXPORT_DIR@#$(EXPORT_DIR)#g'; \
	  echo 's#@''RPL_SSHD_RESTART_COMMAND@#$(SSHD_RESTART_COMMAND)#g'; \
	  echo 's#@''PKGLIBDIR@#$(libdir)/alcor#g'; \
	  echo 's#@''GNTMASTERUSER@#$(MASTERD_USER)#g'; \
	  echo 's#@''GNTRAPIUSER@#$(RAPI_USER)#g'; \
	  echo 's#@''GNTCONFDUSER@#$(CONFD_USER)#g'; \
	  echo 's#@''GNTWCONFDUSER@#$(WCONFD_USER)#g'; \
	  echo 's#@''GNTLUXIDUSER@#$(LUXID_USER)#g'; \
	  echo 's#@''GNTNODEDUSER@#$(NODED_USER)#g'; \
	  echo 's#@''GNTMONDUSER@#$(MOND_USER)#g'; \
	  echo 's#@''GNTMETADUSER@#$(METAD_USER)#g'; \
	  echo 's#@''GNTRAPIGROUP@#$(RAPI_GROUP)#g'; \
	  echo 's#@''GNTADMINGROUP@#$(ADMIN_GROUP)#g'; \
	  echo 's#@''GNTCONFDGROUP@#$(CONFD_GROUP)#g'; \
	  echo 's#@''GNTNODEDGROUP@#$(NODED_GROUP)#g'; \
	  echo 's#@''GNTWCONFDGROUP@#$(CONFD_GROUP)#g'; \
	  echo 's#@''GNTLUXIDGROUP@#$(LUXID_GROUP)#g'; \
	  echo 's#@''GNTMASTERDGROUP@#$(MASTERD_GROUP)#g'; \
	  echo 's#@''GNTMONDGROUP@#$(MOND_GROUP)#g'; \
	  echo 's#@''GNTMETADGROUP@#$(METAD_GROUP)#g'; \
	  echo 's#@''GNTDAEMONSGROUP@#$(DAEMONS_GROUP)#g'; \
	  echo 's#@''CUSTOM_ENABLE_MOND@#$(ENABLE_MOND)#g'; \
	  echo 's#@''XEN_CONFIG_DIR@#$(XEN_CONFIG_DIR)#g'; \
	  echo; \
	  echo '/^@SHELL_ENV_INIT@$$/ {'; \
	  echo '  r $(SHELL_ENV_INIT)'; \
	  echo '  d'; \
	  echo '}'; \
	} > $@

daemons/alcor-%: MODULE = alcor.server.$(patsubst alcor-%,%,$(notdir $@))
daemons/alcor-watcher: MODULE = alcor.watcher
scripts/%: MODULE = alcor.client.$(subst -,_,$(notdir $@))
tools/burnin: MODULE = alcor.tools.burnin
tools/ensure-dirs: MODULE = alcor.tools.ensure_dirs
tools/node-daemon-setup: MODULE = alcor.tools.node_daemon_setup
tools/prepare-node-join: MODULE = alcor.tools.prepare_node_join
tools/ssh-update: MODULE = alcor.tools.ssh_update
tools/node-cleanup: MODULE = alcor.tools.node_cleanup
tools/ssl-update: MODULE = alcor.tools.ssl_update
$(HS_BUILT_TEST_HELPERS): TESTROLE = $(patsubst test/hs/%,%,$@)

$(PYTHON_BOOTSTRAP) $(gnt_scripts) $(gnt_python_sbin_SCRIPTS): Makefile | stamp-directories
	test -n "$(MODULE)" || { echo Missing module; exit 1; }
	set -e; \
	{ echo '#!${PYTHON}'; \
	  echo '# This file is automatically generated, do not edit!'; \
	  echo "# Edit $(MODULE) instead."; \
	  echo; \
	  echo '"""Bootstrap script for L{$(MODULE)}"""'; \
	  echo; \
	  echo '# pylint: disable=C0103'; \
	  echo '# C0103: Invalid name'; \
	  echo; \
	  echo 'import sys'; \
	  echo 'import $(MODULE) as main'; \
	  echo; \
	  echo '# Temporarily alias commands until bash completion'; \
	  echo '# generator is changed'; \
	  echo 'if hasattr(main, "commands"):'; \
	  echo '  commands = main.commands # pylint: disable=E1101'; \
	  echo 'if hasattr(main, "aliases"):'; \
	  echo '  aliases = main.aliases # pylint: disable=E1101'; \
	  echo; \
	  echo 'if __name__ == "__main__":'; \
	  echo '  sys.exit(main.Main())'; \
	} > $@
	chmod u+x $@

$(HS_BUILT_TEST_HELPERS): Makefile
	@test -n "$(TESTROLE)" || { echo Missing TESTROLE; exit 1; }
	set -e; \
	{ echo '#!/bin/sh'; \
	  echo '# This file is automatically generated, do not edit!'; \
	  echo "# Edit Makefile.am instead."; \
	  echo; \
	  echo "HTOOLS=$(TESTROLE) exec ./test/hs/hpc-htools \"\$$@\""; \
	} > $@
	chmod u+x $@

stamp-directories: Makefile
	$(MAKE) $(AM_MAKEFLAGS) alcor
	@mkdir_p@ $(DIRS) $(BUILDTIME_DIR_AUTOCREATE)
	touch $@

stamp-srclinks: Makefile | stamp-directories
	set -e; \
	for i in $(srclink_files); do \
	  if test ! -f $$i -a -f $(abs_top_srcdir)/$$i; then \
	    $(LN_S) $(abs_top_srcdir)/$$i $$i; \
	  fi; \
	done
	touch $@

.PHONY: alcor
alcor:
	cd $(top_builddir) && test -h "$@" || { rm -f $@ && $(LN_S) lib $@; }

.PHONY: check-dirs
check-dirs: $(GENERATED_FILES)
	@set -e; \
	find . -type d \( -name . -o -name .git -prune -o -print \) | { \
	  error=; \
	  while read dir; do \
	    case "$$dir" in \
	      $(strip $(patsubst %,(./%) ;;,$(DIRCHECK_EXCLUDE) $(DIRS))) \
	      *) error=1; echo "Directory $$dir not listed in Makefile" >&2 ;; \
	    esac; \
	  done; \
	  for dir in $(DIRS); do \
	    if ! test -d "$$dir"; then \
	      echo "Directory $$dir listed in DIRS does not exist" >&2; \
	      error=1; \
	    fi \
	  done; \
	  test -z "$$error"; \
	}

.PHONY: check-news
check-news:
	RELEASE=$(PACKAGE_VERSION) $(CHECK_NEWS) < $(top_srcdir)/NEWS

.PHONY: check-local
check-local: check-dirs check-news $(GENERATED_FILES)
	$(CHECK_PYTHON_CODE) $(check_python_code)
	PYTHONPATH=. $(CHECK_HEADER) \
	    $(filter-out $(GENERATED_FILES),$(check_python_code))
	$(CHECK_VERSION) $(VERSION) $(top_srcdir)/NEWS
	PYTHONPATH=. $(RUN_IN_TEMPDIR) $(CURDIR)/$(CHECK_IMPORTS) . $(standalone_python_modules)
	error= ; \
	if [ "x`echo $(VERSION_SUFFIX)|grep 'alpha'`" == "x" ]; then \
	  expver=$(VERSION_MAJOR).$(VERSION_MINOR); \
	  if test "`head -n 1 $(top_srcdir)/README`" != "Alcor $$expver"; then \
	    echo "Incorrect version in README, expected $$expver" >&2; \
	    error=1; \
	  fi; \
	  for file in doc/iallocator.rst doc/hooks.rst doc/virtual-cluster.rst \
	      doc/security.rst; do \
	    if test "`sed -ne '4 p' $(top_srcdir)/$$file`" != \
	      "Documents Alcor version $$expver"; then \
	      echo "Incorrect version in $$file, expected $$expver" >&2; \
	      error=1; \
	    fi; \
	  done; \
	  if ! test -f $(top_srcdir)/doc/design-$$expver.rst; then \
	    echo "File $(top_srcdir)/doc/design-$$expver.rst not found" >&2; \
	    error=1; \
	  fi; \
	  if test "`sed -ne '5 p' $(top_srcdir)/doc/design-draft.rst`" != \
	    ".. Last updated for Alcor $$expver"; then \
	    echo "doc/design-draft.rst was not updated for version $$expver" >&2; \
	    error=1; \
	  fi; \
	fi; \
	for file in configure.ac $(HS_LIBTEST_SRCS) $(HS_PROG_SRCS); do \
	  if test $$(wc --max-line-length < $(top_srcdir)/$$file) -gt 80; then \
	    echo "Longest line in $$file is longer than 80 characters" >&2; \
	    error=1; \
	  fi; \
	done; \
	test -z "$$error"

.PHONY: hs-test-%
hs-test-%: test/hs/htest
	@rm -f htest.tix
	test/hs/htest -t $*

.PHONY: hs-tests
hs-tests: test/hs/htest
	@rm -f htest.tix
	./test/hs/htest

.PHONY: py-tests
py-tests: $(python_tests) alcor $(built_python_sources)
	@if [ "$(PY_NODEV)" ]; then \
	  echo "Error: cannot run unittests without the development" \
	       " libraries (see devnotes.rst)" 1>&2; \
	  exit 1; \
	fi
	error=; \
	for file in $(python_tests); \
	  do if ! $(TESTS_ENVIRONMENT) $$file; then error=1; fi; \
	done; \
	test -z "$$error"

.PHONY: hs-shell-%
hs-shell-%: test/hs/hpc-htools test/hs/hpc-mon-collector \
            $(HS_BUILT_TEST_HELPERS)
	@rm -f hpc-htools.tix hpc-mon-collector.tix
	HBINARY="./test/hs/hpc-htools" \
	SHELLTESTARGS=$(SHELLTESTARGS) \
	./test/hs/offline-test.sh $*

.PHONY: hs-shell
hs-shell: test/hs/hpc-htools test/hs/hpc-mon-collector $(HS_BUILT_TEST_HELPERS)
	@rm -f hpc-htools.tix hpc-mon-collector.tix
	HBINARY="./test/hs/hpc-htools" \
	SHELLTESTARGS=$(SHELLTESTARGS) \
	./test/hs/offline-test.sh

.PHONY: hs-check
hs-check: hs-tests hs-shell

PEP8_IGNORE = E111,E114,E121,E123,E125,E127,E261,E501

PEP8_EXCLUDE = $(subst $(space),$(comma),$(strip $(notdir $(built_python_sources))))

LINT_DISABLE = I0013 R0912 R0204 C0325 C0330
LINT_OPTS =
LINT_OPTS_ALL = $(LINT_OPTS) \
  $(addprefix --disable=,$(LINT_DISABLE))

LINT_OPTS_ALL += --extension-pkg-whitelist=pycurl

LINT_TARGETS = pylint pylint-qa pylint-test
if HAS_PYCODESTYLE
LINT_TARGETS += pycodestyle
endif
if HAS_HLINT
LINT_TARGETS += hlint
endif

.PHONY: lint
lint: $(LINT_TARGETS)

.PHONY: pylint
pylint: $(GENERATED_FILES)
	@test -n "$(PYLINT)" || { echo 'pylint' not found during configure; exit 1; }
	$(PYLINT) $(LINT_OPTS_ALL) $(lint_python_code)

.PHONY: pylint-qa
pylint-qa: $(GENERATED_FILES)
	@test -n "$(PYLINT)" || { echo 'pylint' not found during configure; exit 1; }
	cd $(top_srcdir)/qa && \
	  PYTHONPATH=$(abs_top_srcdir) $(PYLINT) $(LINT_OPTS_ALL) \
		--rcfile  ../pylintrc $(patsubst qa/%.py,%,$(qa_scripts))
pylint-test: $(GENERATED_FILES)
	@test -n "$(PYLINT)" || { echo 'pylint' not found during configure; exit 1; }
	cd $(top_srcdir) && \
		PYTHONPATH=.:./test/py $(PYLINT) $(LINT_OPTS_ALL) \
		--rcfile=pylintrc-test  $(python_test_support) $(python_test_utils)

.PHONY: pycodestyle
pycodestyle: $(GENERATED_FILES)
	@test -n "$(PYCODESTYLE)" || { echo 'pycodestyle' not found during configure; exit 1; }
	$(PYCODESTYLE) --ignore='$(PEP8_IGNORE)' --exclude='$(PEP8_EXCLUDE)' \
	--repeat $(pycodestyle_python_code)

pycodestyle-stats: $(GENERATED_FILES)
	@test -n "$(PYCODESTYLE)" || { echo 'pycodestyle' not found during configure; exit 1; }
	$(PYCODESTYLE) --ignore='$(PEP8_IGNORE)' --exclude='$(PEP8_EXCLUDE)' \
	--repeat --statistics $(pycodestyle_python_code)

HLINT_EXCLUDES = src/Alcor/THH.hs test/hs/hpc-htools.hs
.PHONY: hlint
hlint: $(HS_BUILT_SRCS) src/lint-hints.hs
	@test -n "$(HLINT)" || { echo 'hlint' not found during configure; exit 1; }
	@rm -f doc/hs-lint.html
	if tty -s; then C="-c"; else C=""; fi; \
	$(HLINT) --report=doc/hs-lint.html --cross $$C \
	  --hint src/lint-hints \
	  --cpp-file=$(HASKELL_PACKAGE_VERSIONS_FILE) \
	  $(filter-out $(HLINT_EXCLUDES),$(HS_LIBTEST_SRCS) $(HS_PROG_SRCS))
	@if [ ! -f doc/hs-lint.html ]; then \
	  echo "All good" > doc/hs-lint.html; \
	fi

dist-hook:
	$(MAKE) $(AM_MAKEFLAGS) regen-vcs-version
	rm -f $(top_distdir)/vcs-version
	cp -p $(srcdir)/vcs-version $(top_distdir)

distcheck-hook:
	if find $(top_distdir) -name .svn -or -name .git | grep .; then \
	  echo "Found revision control files in final archive." 1>&2; \
	  exit 1; \
	fi
	if find $(top_distdir) -name '*.py[co]' | grep .; then \
	  echo "Found Python byte code in final archive." 1>&2; \
	  exit 1; \
	fi
	if find $(top_distdir) -name '*~' | grep .; then \
	  echo "Found backup files in final archive." 1>&2; \
	  exit 1; \
	fi
	if find $(top_distdir) -empty -and -not \( \
	    -regex '$(top_distdir)/_build\(/.*\)?' -or \
	    -path $(top_distdir)/_inst \) | grep .; then \
	  echo "Found empty files or directories in final archive." 1>&2; \
	  exit 1; \
	fi
	if test -e $(top_distdir)/doc/man-html; then \
	  echo "Found documentation including man pages in final archive" >&2; \
	  exit 1; \
	fi

distcheck-release: distcheck

distrebuildcheck: dist
	set -e; \
	builddir=$$(mktemp -d $(abs_srcdir)/distrebuildcheck.XXXXXXX); \
	trap "echo Removing $$builddir; cd $(abs_srcdir); rm -rf $$builddir" EXIT; \
	cd $$builddir; \
	tar xzf $(abs_srcdir)/$(distdir).tar.gz; \
	cd $(distdir); \
	./configure; \
	$(MAKE) maintainer-clean; \
	cp $(abs_srcdir)/vcs-version .; \
	./configure; \
	$(MAKE) $(AM_MAKEFLAGS)

dist-release: dist
	set -e; \
	for i in $(DIST_ARCHIVES); do \
	  echo -n "Checking $$i ... "; \
	  autotools/check-tar < $$i; \
	  echo OK; \
	done

install-exec-local:
	@mkdir_p@ "$(DESTDIR)${localstatedir}/lib/alcor" \
	  "$(DESTDIR)${localstatedir}/log/alcor" \
	  "$(DESTDIR)${localstatedir}/run/alcor"
	for dir in $(SYMLINK_TARGET_DIRS); do \
	  @mkdir_p@  $(DESTDIR)$$dir; \
	done
	$(LN_S) -f $(sysconfdir)/alcor/lib $(DESTDIR)$(defaultversiondir)
	$(LN_S) -f $(sysconfdir)/alcor/share $(DESTDIR)$(defaultversionedsharedir)
	for prog in $(HS_BIN_ROLES); do \
	  $(LN_S) -f $(defaultversiondir)$(BINDIR)/$$prog $(DESTDIR)$(BINDIR)/$$prog; \
	done
	$(LN_S) -f $(defaultversiondir)$(libdir)/alcor/iallocators/hail $(DESTDIR)$(libdir)/alcor/iallocators/hail
	for prog in $(all_sbin_scripts); do \
	  $(LN_S) -f $(defaultversiondir)$(SBINDIR)/$$prog $(DESTDIR)$(SBINDIR)/$$prog; \
	done
	for prog in $(gnt_scripts_basenames); do \
	  $(LN_S) -f $(defaultversionedsharedir)/$$prog $(DESTDIR)$(SBINDIR)/$$prog; \
	done
	for prog in $(pkglib_python_basenames); do \
	  $(LN_S) -f $(defaultversionedsharedir)/$$prog $(DESTDIR)$(libdir)/alcor/$$prog; \
	done
	for prog in $(tools_python_basenames); do \
	  $(LN_S) -f $(defaultversionedsharedir)/$$prog $(DESTDIR)$(libdir)/alcor/tools/$$prog; \
	done
	for prog in $(tools_basenames); do \
	  $(LN_S) -f $(defaultversiondir)/$(libdir)/alcor/tools/$$prog $(DESTDIR)$(libdir)/alcor/tools/$$prog; \
	done
	if ! test -n '$(ENABLE_MANPAGES)'; then \
	  for man in $(manfullpath); do \
	    $(LN_S) -f $(defaultversionedsharedir)/root$(MANDIR)/$$man $(DESTDIR)$(MANDIR)/$$man; \
	  done; \
	fi
	for prog in $(myexeclib_scripts_basenames); do \
	  $(LN_S) -f $(defaultversiondir)$(libdir)/alcor/$$prog $(DESTDIR)$(libdir)/alcor/$$prog; \
	done
if INSTALL_SYMLINKS
	$(LN_S) -f $(versionedsharedir) $(DESTDIR)$(sysconfdir)/alcor/share
	$(LN_S) -f $(versiondir) $(DESTDIR)$(sysconfdir)/alcor/lib
endif

.PHONY: apidoc
if WANT_HSAPIDOC
apidoc: py-apidoc hs-apidoc
else
apidoc: py-apidoc
endif

.PHONY: py-apidoc
py-apidoc:
	$(RUN_IN_TEMPDIR) pydoctor -v \
	  --config $(CURDIR)/pydoctor.ini \
	  --html-output $(CURDIR)/$(APIDOC_PY_DIR) \
	  $(lint_python_code)

.PHONY: hs-apidoc
hs-apidoc: $(APIDOC_HS_DIR)/index.html

$(APIDOC_HS_DIR)/index.html: $(HS_LIBTESTBUILT_SRCS) Makefile
	@test -n "$(HSCOLOUR)" || \
	    { echo 'HsColour' not found during configure; exit 1; }
	@test -n "$(HADDOCK)" || \
	    { echo 'haddock' not found during configure; exit 1; }
	rm -rf $(APIDOC_HS_DIR)/*
	for i in $(ALL_APIDOC_HS_DIRS); do \
	  @mkdir_p@ $$i; \
	  $(HSCOLOUR) -print-css > $$i/hscolour.css; \
	done
	set -e ; \
	export LC_ALL=$(UTF8_LOCALE); \
	OPTGHC="--optghc=-isrc --optghc=-itest/hs"; \
	OPTGHC="$$OPTGHC --optghc=-optP-include --optghc=-optP$(HASKELL_PACKAGE_VERSIONS_FILE)"; \
	for file in $(HS_LIBTESTBUILT_SRCS); do \
	  f_nosrc=$${file##src/}; \
	  f_notst=$${f_nosrc##test/hs/}; \
	  f_html=$${f_notst%%.hs}.html; \
	  $(HSCOLOUR) -css -anchor $$file > $(APIDOC_HS_DIR)/$$f_html ; \
	done ; \
	$(HADDOCK) --odir $(APIDOC_HS_DIR) --html --hoogle --ignore-all-exports -w \
	  -t alcor -p src/haddock-prologue \
	  --source-module="%{MODULE/.//}.html" \
	  --source-entity="%{MODULE/.//}.html#%{NAME}" \
	  $$OPTGHC \
	  $(HS_LIBTESTBUILT_SRCS)

.PHONY: TAGS
TAGS: $(GENERATED_FILES)
	rm -f TAGS
	$(GHC) -e ":etags TAGS_hs" -v0 \
	  $(filter-out -O -Werror,$(HFLAGS)) \
		-osuf tags.o \
		-hisuf tags.hi \
	-lcurl \
	  $(HS_LIBTEST_SRCS)
	find . -path './lib/*.py' -o -path './scripts/gnt-*' -o \
	  -path './daemons/alcor-*' -o -path './tools/*' -o \
	  -path './qa/*.py' | \
	  etags --etags-include=TAGS_hs -L -

.PHONY: coverage

COVERAGE_TESTS=
if HS_UNIT
COVERAGE_TESTS += hs-coverage
endif
if PY_UNIT
COVERAGE_TESTS += py-coverage
endif

coverage: $(COVERAGE_TESTS)

test/py/docs_unittest.py: $(gnt_scripts)

.PHONY: py-coverage
py-coverage: $(GENERATED_FILES) $(python_tests)
	@test -n "$(PYCOVERAGE)" || \
	    { echo 'python-coverage' not found during configure; exit 1; }
	set -e; \
	COVERAGE=$(PYCOVERAGE) \
	COVERAGE_FILE=$(CURDIR)/$(COVERAGE_PY_DIR)/data \
	TEXT_COVERAGE=$(CURDIR)/$(COVERAGE_PY_DIR)/report.txt \
	HTML_COVERAGE=$(CURDIR)/$(COVERAGE_PY_DIR) \
	$(PLAIN_TESTS_ENVIRONMENT) \
	$(abs_top_srcdir)/autotools/gen-py-coverage \
	$(python_tests)

.PHONY: hs-coverage
hs-coverage: $(haskell_tests) test/hs/hpc-htools test/hs/hpc-mon-collector
	rm -f *.tix
	$(MAKE) $(AM_MAKEFLAGS) hs-check
	@mkdir_p@ $(COVERAGE_HS_DIR)
	hpc sum --union $(HPCEXCL) \
	  htest.tix hpc-htools.tix hpc-mon-collector.tix > coverage-hs.tix
	hpc markup --destdir=$(COVERAGE_HS_DIR) coverage-hs.tix
	hpc report coverage-hs.tix | tee $(COVERAGE_HS_DIR)/report.txt
	$(LN_S) -f hpc_index.html $(COVERAGE_HS_DIR)/index.html

.PHONY: live-test
live-test: all
	set -e ; \
	cd src; \
	rm -f .hpc; $(LN_S) ../.hpc .hpc; \
	rm -f *.tix *.mix; \
	./live-test.sh; \
	hpc sum --union $(HPCEXCL) $(addsuffix .tix,$(HS_PROGS:src/%=%)) \
	  --output=live-test.tix ; \
	@mkdir_p@ ../$(COVERAGE_HS_DIR) ; \
	hpc markup --destdir=../$(COVERAGE_HS_DIR) live-test \
	  --srcdir=.. $(HPCEXCL) ; \
	hpc report --srcdir=.. live-test $(HPCEXCL)

commit-check: autotools-check distcheck lint apidoc

autotools-check:
	TESTDATA_DIR=./test/data shelltest $(SHELLTESTARGS) \
  $(abs_top_srcdir)/test/autotools/*-*.test \
  -- --hide-successes

.PHONY: gitignore-check
gitignore-check:
	@if [ -n "`git status --short`" ]; then \
	  echo "Git status is not clean!" 1>&2 ; \
	  git status --short; \
	  exit 1; \
	fi

.PHONY: man
man: $(man_MANS) $(manhtml)

CABAL_EXECUTABLES = $(HS_DEFAULT_PROGS)
CABAL_EXECUTABLES_HS = $(patsubst %,%.hs,$(CABAL_EXECUTABLES))
CABAL_EXECUTABLES_APPS_STAMPS = $(patsubst src/%,apps/%.hs.stamp,$(patsubst test/hs/%,apps/%.hs.stamp,$(CABAL_EXECUTABLES)))

apps/%.hs.stamp: Makefile
	mkdir -p apps
	rm -f $(basename $@)
	ln -s ../$(filter %/$(basename $(notdir $@)),$(CABAL_EXECUTABLES_HS)) $(basename $@)
	touch $@

alcor.cabal: cabal/alcor.template.cabal Makefile cabal/cabal-from-modules.py $(CABAL_EXECUTABLES_APPS_STAMPS)
	@echo $(subst /,.,$(patsubst %.hs,%,$(patsubst test/hs/%,%,$(patsubst src/%,%,$(HS_SRCS))))) \
	  | $(PYTHON) $(abs_top_srcdir)/cabal/cabal-from-modules.py $(abs_top_srcdir)/cabal/alcor.template.cabal > $@

	for p in $(CABAL_EXECUTABLES); do \
	  echo                                   >> $@; \
	  echo "executable `basename $$p`"       >> $@; \
	  echo "  hs-source-dirs: apps"          >> $@; \
	  echo "  main-is: `basename $$p`.hs"    >> $@; \
	  echo "  default-language: Haskell2010" >> $@; \
	  echo "  build-depends:"                >> $@; \
	  echo "      base"                      >> $@; \
	  echo "    , alcor"                    >> $@; \
	  if [ $$p == test/hs/htest ]; then \
	    echo "    , hslogger"                  >> $@; \
	    echo "    , test-framework"            >> $@; \
	  elif [ $$p == src/rpc-test ]; then \
	    echo "    , json"                      >> $@; \
	  fi \
	done

.PHONY: really-all
really-all: all $(check_SCRIPTS) $(haskell_tests) $(HS_ALL_PROGS)

%: %,v
%: RCS/%,v
%: RCS/%
%: s.%
%: SCCS/s.%

-include ./Makefile.local


print-%:
	@echo $($*)

