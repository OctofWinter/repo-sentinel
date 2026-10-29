# Security policy

The initial supported version is 0.1.x. This tool performs a limited set of local checks and should complement code review and dedicated secret scanning.

If the repository's Security tab offers **Report a vulnerability**, please use that private reporting route. Otherwise use a contact method listed by the maintainer on their GitHub profile. If neither route is available, open an issue asking for a private contact channel without including vulnerability details. Include the affected version, a minimal reproduction using synthetic data, and expected versus observed behavior in the subsequent private report. Do not send live tokens or private repository contents.

The scanner performs no outbound requests and does not write files. It omits matched values and source lines from findings. Reports still contain file paths; review them before sharing. Scan stable directories under your control, not concurrently modified or attacker-controlled filesystems.
