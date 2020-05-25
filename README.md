# mft-scripts

Just a small collection of scripts I wrote while working with Mellanox firmware images.

## **mfa_extract.py**

Allows to extract .bin firmware images for a specific PSID from a .mfa bundle.


## **update_ini.py**

Allows to replace the "Firmware Configuration" section in a .bin firmware file.

## **update2_ini.py**

Allows to replace the "Firmware Configuration" section in a .bin firmware file.
This version does not depend on `mstflint` binary for CRC calculations so it works a bit slower.
