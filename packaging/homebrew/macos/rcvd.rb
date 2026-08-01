# Homebrew formula for rcvd — privacy-first DNS engine (DoQ/DoT/DoH, no cleartext).
# === macOS variant === (Linux/Linuxbrew has its own: packaging/homebrew/linux/rcvd.rb).
# Deliberately split per-OS: each formula is a plain single-OS file rather than one file
# full of on_macos/on_linux conditionals. The macOS-specific parts are the DoQ sysctl
# caveats (net.inet.udp.*) and the launchd service brew generates from the service block.
#
# STATUS: pre-release. rcvd is not yet published with a tagged release tarball, so the
# `stable` url/sha256 below are PLACEHOLDERS. Until a release is cut, install and test
# from git head:
#
#     brew install --HEAD ./packaging/homebrew/macos/rcvd.rb
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
    # the binary static; -trimpath + -s -w mirror scripts/build-macos-amd64.sh.
    build_date = Utils.safe_popen_read("date", "-u", "+%Y-%m-%dT%H:%M:%SZ").strip
    ldflags = "-s -w -X main.buildDate=#{build_date} -X main.buildSource=homebrew"
    ENV["CGO_ENABLED"] = "0"
    system "go", "build", *std_go_args(ldflags: ldflags, output: bin/"rcvd"), "./cmd/rcvd"

    # Man page: install the checked-in roff (generated from man/rcvd.1.md via go-md2man).
    man1.install "man/rcvd.1" if File.exist?("man/rcvd.1")

    # Example configs go to the formula's share dir — NOT auto-activated. The user copies
    # one to #{etc}/rcvd/rcvd.toml (or symlinks a profile) before starting the service.
    # Guarded so an empty glob doesn't warn (Dir[] may match nothing in a given tree).
    examples = Dir["etc/*.toml"]
    pkgshare.install examples unless examples.empty?
  end

  # Homebrew runs `brew services` as the invoking user by default. rcvd on port 5300 needs
  # no privilege, so no `require_root`. Config is #{etc}/rcvd/rcvd.toml.
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
      rcvd speaks QUIC by default, and macOS ships small UDP socket buffers, so quic-go
      may warn "failed to sufficiently increase receive buffer size". rcvd still works
      without tuning (smaller buffers, marginally lower throughput). To raise them now:

        sudo sysctl -w net.inet.udp.recvspace=7340032
        sudo sysctl -w net.inet.udp.sendspace=7340032
        sudo sysctl -w kern.ipc.maxsockbuf=8388608

      To persist across reboots, add to /etc/sysctl.conf:

        net.inet.udp.recvspace=7340032
        net.inet.udp.sendspace=7340032
        kern.ipc.maxsockbuf=8388608
    EOS
  end

  test do
    assert_match "rcvd", shell_output("#{bin}/rcvd --version")
  end
end
