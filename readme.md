# EspreSSHo - SSH keys on hard cards

EspreSSHo is a project to hold SSH keys (specifically Elliptic Curve keys) on a JavaCard.

* up to 4 keys
* Each key has
  * PIN-on-use requirement
  * PIN timeout
  * Wipe-on-block

## Mokapot: the JavaCard part

Mokapot handles the keys themselves and talks over PDUs to the host side

It handles

* Generating up to 4 keys
* PIN management
* Key wiping
* Signing for SSH

## Barista: The SSH agent part


Barista is a Go program that acts as an SSH agent. It handles talking between the SSH client (or Git) and Bean through the PC/SC interface (or NFC)
