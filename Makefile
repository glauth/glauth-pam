# Note: to make a plugin compatible with a binary built in debug mode, add `-gcflags='all=-N -l'`

PLUGIN_OS ?= linux
PLUGIN_ARCH ?= amd64

plugin_pam: bin/$(PLUGIN_OS)$(PLUGIN_ARCH)/pam_linux.so

bin/$(PLUGIN_OS)$(PLUGIN_ARCH)/pam_linux.so: pkg/plugins/glauth-pam/pam.go
	GOOS=$(PLUGIN_OS) GOARCH=$(PLUGIN_ARCH) go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -buildmode=plugin -o $@ $^

plugin_pam_linux_amd64:
	PLUGIN_OS=linux PLUGIN_ARCH=amd64 make plugin_pam

plugin_pam_linux_arm64:
	PLUGIN_OS=linux PLUGIN_ARCH=arm64 make plugin_pam

plugin_pam_darwin_amd64:
	PLUGIN_OS=darwin PLUGIN_ARCH=amd64 make plugin_pam

plugin_pam_darwin_arm64:
	PLUGIN_OS=darwin PLUGIN_ARCH=arm64 make plugin_pam

release-glauth-pam: plugin_pam_linux_amd64
	mv bin/linuxamd64/pam_linux.so bin/pam_linux-linux-amd64.so && rmdir bin/linuxamd64
