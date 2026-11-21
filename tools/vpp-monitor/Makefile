# Builds Linux executables from any platform.
ARCHES ?= arm64 amd64
OUT ?= dist

BINARIES := $(ARCHES:%=$(OUT)/vpp-monitor-linux-%)

.PHONY: all clean $(BINARIES)

all: $(BINARIES)

$(BINARIES): $(OUT)/vpp-monitor-linux-%:
	CGO_ENABLED=0 GOOS=linux GOARCH=$* go build -trimpath -ldflags='-s -w' -o $@ .

clean:
	rm -rf $(OUT)
