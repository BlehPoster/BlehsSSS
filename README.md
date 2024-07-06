# Bleh'sSSS
Bleh's Shamir’s Secret Sharing

## !!! WIP !!!
This repository contains an implementation of Shamir's Secret Sharing where shares are protected using Elliptic Curve Integrated Encryption Scheme (ECIES) and verified via Edwards-Curve Digital Signature Algorithm (EDDSA). Shamir's Secret Sharing is a cryptographic technique that allows a secret to be divided into shares, which can then be distributed among a group of participants. The original secret can be reconstructed only when a sufficient number of shares are combined.
ECIES is used to securely encrypt and decrypt the shares, adding an extra layer of security to the Shamir's Secret Sharing scheme.
EDDSA is a verification mechanism to verify the validity of the data.

#### Goals
 [x] ED25519 implementation  
 [x] C25519 implementation  
 [x] ECIES X25519 implementation  
 [x] SSS implementation  
 [x] Simple CLI to test functionality  
 [ ] Unit tests  
 [ ] ...  

#### Usage
    blesss_cli [command] --[args ...]
    
    # create shares
    cli sss-share --secret="hallo world" --shares=5 --min=2 --out=data\shares.dat
    # recreate to check if the shares are valid
    cli sss-recreate --out=data\shares.dat

    # create account
    cli account-create --name=bleh --out=data\blehsss-account-bleh.dat

    # export and verify account
    cli account-public-export --account=data\blehsss-account-bleh.dat --out=data\blehsss-account-public-bleh.dat
    cli account-public-verify --public=data\blehsss-account-public-bleh.dat

    # encrypt share for account bleh
    cli transportable-share --public-part=data\blehsss-account-public-bleh.dat --share-file=data\shares.dat --share-number=1 --account=data\blehsss-account-bleh.dat --out=data\encrypted-share-bleh.dat

    # decrypt share for account bleh
    cli share_print --share-file=data\encrypted-share-bleh.dat --account=data\blehsss-account-bleh.dat

#### License
This project is licensed under the MIT License. Feel free to use, modify, and distribute the code as per the terms of this license.
