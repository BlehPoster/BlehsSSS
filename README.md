# Bleh'sSSS
Bleh's Shamir’s Secret Sharing

## !!! WIP !!!
This repository contains an implementation of Shamir's Secret Sharing where shares are protected using Elliptic Curve Integrated Encryption Scheme (ECIES) and verified via EDDSA. Shamir's Secret Sharing is a cryptographic technique that allows a secret to be divided into shares, which can then be distributed among a group of participants. The original secret can be reconstructed only when a sufficient number of shares are combined.
ECIES is used to securely encrypt and decrypt the shares, adding an extra layer of security to the Shamir's Secret Sharing scheme.
EDDSA is a verification mechanism to verify the validity of the data.

#### Goals
[x] - ED25519 implementation
[x] - C25519 implementation
[x] - ECIES X25519 implementation
[x] - SSS implementation
[-] - Unit tests
[-] - Simple CLI to test functionality
[-] - ...

#### Usage
    // TODO

#### License
This project is licensed under the MIT License. Feel free to use, modify, and distribute the code as per the terms of this license.