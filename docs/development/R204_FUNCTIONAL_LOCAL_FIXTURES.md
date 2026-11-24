# R204 - Functional SSH and SMB fixtures

Bounded functional software checks using Paramiko 5.0.0
and Impacket 0.13.1.

Each server and client pair runs inside a separate local
network namespace with only the loopback interface and
zero effective Linux capabilities.

SSH validates temporary public-key authentication,
server identity and a fixed diagnostic subsystem.
No operating system shell or arbitrary commands are exposed.

SMB validates an authorized read of a synthetic file
from a dedicated read-only share. No user files or
external destinations are accepted.

Temporary credentials are not persisted in reports.
Plans and attempts are recorded before execution.
An unsuccessful attempt is not retried automatically.

These checks do not establish production OpenSSH or
Samba equivalence, independently attested isolation,
physical experimental admission or historical authority.

Previous FTP results are reused without new execution.

A6 remains ND; confirmed Rf and operational A9 remain
unavailable. P7 is draft and P8 remains NO-GO.
