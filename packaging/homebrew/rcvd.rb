# Homebrew formula for rcvd, a privacy-first DNS engine (DoQ/DoT/DoH, no cleartext).
#
# One formula for both macOS and Linux (Linuxbrew): a tap holds a single
# Formula/rcvd.rb, so per-OS differences live in OS.mac? branches below. The
# published copy lives in the rcvd-dns/homebrew-rcvd tap; this file is its source.
#
# Homebrew only installs formulae from a tap, so test through the tap:
#
#     brew install --build-from-source rcvd-dns/rcvd/rcvd
#     brew test rcvd && brew audit --strict --new rcvd-dns/rcvd/rcvd
class Rcvd < Formula
  desc "Privacy-first DNS engine with encrypted DoQ/DoT/DoH egress and no cleartext"
  homepage "https://rcvd.net"
  url "https://github.com/rcvd-dns/rcvd/archive/refs/tags/v0.3.0.tar.gz"
  sha256 "2252b6d071f7a7a2a2ae804add48263bc19bf87784b16bec97ef6f9afb422f47"
  license "MIT"
  head "https://github.com/rcvd-dns/rcvd.git", branch: "main"

  depends_on "go" => :build

  def install
    # Static and build-stamped; std_go_args adds -s -w and -trimpath. time is
    # the formula's source date, so the stamp is reproducible.
    ldflags = %W[
      -X main.version=#{version}
      -X main.buildDate=#{time.iso8601}
      -X main.buildSource=homebrew
    ]
    ENV["CGO_ENABLED"] = "0"
    system "go", "build", *std_go_args(ldflags:), "./cmd/rcvd"

    man1.install "man/rcvd.1"
    # Example configs only; nothing is activated until the user provides a config.
    pkgshare.install Dir["etc/*.toml"]
  end

  post_install_steps do
    mkdir_p "rcvd", base: :etc
    mkdir_p "log/rcvd", base: :var
  end

  # Port 5300 needs no privilege, so the service runs as the invoking user
  # (launchd agent on macOS, systemd user unit on Linux).
  service do
    run [opt_bin/"rcvd", "-config", etc/"rcvd/rcvd.toml"]
    keep_alive true
    log_path var/"log/rcvd/rcvd.log"
    error_log_path var/"log/rcvd/rcvd.log"
    working_dir var
  end

  def caveats
    sysctl = if OS.mac?
      %w[net.inet.udp.recvspace=7340032 net.inet.udp.sendspace=7340032 kern.ipc.maxsockbuf=8388608]
    else
      %w[net.core.rmem_max=7340032 net.core.wmem_max=7340032]
    end
    persist = OS.mac? ? "/etc/sysctl.conf" : "/etc/sysctl.d/60-rcvd-quic.conf"

    <<~EOS
      rcvd is not active until it has a config. Copy a bundled example:

        cp #{opt_pkgshare}/mode1-forwarder-3providers.toml #{etc}/rcvd/rcvd.toml

      (Other examples are in #{opt_pkgshare}.) Then start the service:

        brew services start rcvd

      rcvd speaks QUIC (DoQ) by default. If quic-go warns "failed to sufficiently
      increase receive buffer size", raise the kernel UDP buffer limits. rcvd still
      works without this, with slightly lower throughput.

      #{sysctl.map { |kv| "  sudo sysctl -w #{kv}" }.join("\n")}

      To persist across reboots, add the same keys to #{persist}.
    EOS
  end

  test do
    assert_match "v#{version}", shell_output("#{bin}/rcvd -version")
    assert_path_exists pkgshare/"mode1-forwarder-3providers.toml"
  end
end
