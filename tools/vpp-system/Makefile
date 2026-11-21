# Builds Linux executables from any platform. The program does not run elsewhere.
ARCHES ?= arm64 amd64
OUT ?= dist

BINARIES := $(ARCHES:%=$(OUT)/vpp-system-linux-%)

.PHONY: all clean

all: $(BINARIES)

# Always rebuild: go build decides what is out of date.
.PHONY: $(BINARIES)
$(BINARIES): $(OUT)/vpp-system-linux-%:
	CGO_ENABLED=0 GOOS=linux GOARCH=$* go build -trimpath -o $@ .

clean:
	rm -rf $(OUT)
