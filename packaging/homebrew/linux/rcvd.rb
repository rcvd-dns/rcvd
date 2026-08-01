# Homebrew formula for rcvd — privacy-first DNS engine (DoQ/DoT/DoH, no cleartext).
# === Linux / Linuxbrew variant === (macOS has its own: packaging/homebrew/macos/rcvd.rb).
# Deliberately split per-OS: each formula is a plain single-OS file rather than one file
# full of on_macos/on_linux conditionals. The Linux-specific parts are the DoQ sysctl
# caveats (net.core.rmem_max/wmem_max) and the systemd unit brew generates from the
# service block.
#
# Why Linuxbrew matters for rcvd: native distro packaging (.deb/.rpm) is long-term goal, so
# `brew install rcvd` on Linux is expected to be the primary install path there for a
# good while — a first-class target, not an afterthought.
#
# STATUS: pre-release. rcvd is not yet published with a tagged release tarball, so the
# `stable` url/sha256 below are PLACEHOLDERS. Until a release is cut, install and test
# from git head:
#
#     brew install --HEAD ./packaging/homebrew/linux/rcvd.rb
#
# When a release is tagged, fill in `url` + `sha256` (see PLACEHOLDER markers) and drop
# the `--HEAD` requirement. This formula will live in a third-party tap (rcvd-dns/rcvd);
# on Homebrew 6.0.0+ that tap is untrusted-by-default — see packaging/HOMEBREW-NOTES.md.
class Rcvd < Formula
  desc "Privacy-first DNS engine — encrypted egress over DoQ/DoT/DoH, no cleartext"
  homepage "https://rcvd.net"
  # PLACEHOLDER — populate url + sha256 when the first release is tagged. The version is
  # scanned from the url tag, so do NOT add a redundant `version` line.
  url "https://github.com/rcvd-dns/rcvd/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license "MIT"
  head "https://github.com/rcvd-dns/rcvd.git", branch: "main"

  depends_on "go" => :build

  def install
    # Match the release recipe (static, stripped, trimmed, build-stamped). CGO off keeps
    # the binary static; -trimpath + -s -w mirror scripts/build-linux-amd64.sh.
    build_date = Utils.safe_popen_read("date", "-u", "+%Y-%m-%dT%H:%M:%SZ").strip
    ldflags = "-s -w -X main.buildDate=#{build_date} -X main.buildSource=homebrew"
    ENV["CGO_ENABLED"] = "0"
    system "go", "build", *std_go_args(ldflags: ldflags, output: bin/"rcvd"), "./cmd/rcvd"

    # Man page: install the checked-in roff (generated from man/rcvd.1.md via go-md2man).
    man1.install "man/rcvd.1" if File.exist?("man/rcvd.1")

    # Example configs go to the formula's share dir — NOT auto-activated. The user copies
    # one to #{etc}/rcvd/rcvd.toml before starting the service.
    # Guarded so an empty glob doesn't warn (Dir[] may match nothing in a given tree).
    examples = Dir["etc/*.toml"]
    pkgshare.install examples unless examples.empty?
  end

  # On Linux, `brew services` generates a systemd unit from this block. rcvd on port 5300
  # needs no privilege, so it runs as the invoking user — no root required.
  service do
    run [opt_bin/"rcvd", "-config", etc/"rcvd/rcvd.toml"]
    keep_alive true
    log_path var/"log/rcvd/rcvd.log"
    error_log_path var/"log/rcvd/rcvd.log"
    working_dir var
  end

  def caveats
    <<~EOS
      rcvd is not yet activated. Provide a config first, e.g. copy a bundled example:

        mkdir -p #{etc}/rcvd
        cp #{opt_pkgshare}/mode1-forwarder-3providers.toml #{etc}/rcvd/rcvd.toml

      (See #{opt_pkgshare} for the other example configs.) Then start the service:

        brew services start rcvd

      DoQ (QUIC) tuning — RECOMMENDED:
      rcvd speaks QUIC by default. If quic-go warns "failed to sufficiently increase
      receive buffer size", raise the kernel UDP buffer ceilings (Linux uses net.core.*,
      not the macOS net.inet.udp.* keys). rcvd still works without tuning (smaller
      buffers, marginally lower throughput). To raise them now:

        sudo sysctl -w net.core.rmem_max=7340032
        sudo sysctl -w net.core.wmem_max=7340032

      To persist across reboots, drop a file in /etc/sysctl.d/, e.g.
      /etc/sysctl.d/60-rcvd-quic.conf:

        net.core.rmem_max=7340032
        net.core.wmem_max=7340032
    EOS
  end

  test do
    assert_match "rcvd", shell_output("#{bin}/rcvd --version")
  end
end
