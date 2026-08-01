rcvd(1) manpage
===============

Files
-----
  rcvd.1.md       Markdown source — EDIT THIS
  rcvd.1          Rendered roff manpage — GENERATED from rcvd.1.md.
  Containerfile   Throwaway Ubuntu image for viewing the manpage.

Workflow
--------
After editing rcvd.1.md, always re-render before rebuilding the container
or installing the manpage. The image COPYs rcvd.1, not rcvd.1.md.

  1. Edit:    rcvd.1.md
  2. Render:  ~/go/bin/go-md2man -in rcvd.1.md -out rcvd.1
  3. View:    podman build -t rcvd-man-test . && \
              podman run --rm rcvd-man-test cat /usr/share/man/man1/rcvd.1 | man -l -
  4. Clean:   podman rmi rcvd-man-test

go-md2man toolchain
---------
Pure-Go manpage renderer. No pandoc or groff toolchain needed.
Same tool used by Docker, Podman, and containerd for their manpages.

Install (if not present):
  go install github.com/cpuguy83/go-md2man/v2@latest

Binary lands at ~/go/bin/go-md2man.

Installation (system)
---------------------
  install -m 644 rcvd.1 /usr/share/man/man1/rcvd.1
  mandb
