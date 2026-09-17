# Changelog

## 0.1.2

- Reserve packet headroom in the external TUN receive bridge so OpenVPN Core
  can prepend data-channel framing, including for CBC sessions.
- Check the received packet content and headroom in the native callback
  self-test.
