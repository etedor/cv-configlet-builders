# auto-description

Automatically configure interface descriptions based on neighbor device details.

## Example

```none
interface Port-Channel1
   description SW-GARAGE
interface Ethernet6/3
   description SW-GARAGE, TE1/1/3
interface Ethernet6/4
   description SW-GARAGE, TE1/1/4
interface Ethernet7/1
   description INTELCOR, 97:88:CE
interface Ethernet7/3
   description SW-OFFICE, 10GIGABITETHERNET1/3/1
interface Ethernet7/4
   description SW-LIVING-ROOM, 10GIGABITETHERNET1/3/1
```

## Usage

Add `!! no auto-description` to interfaces where auto-description is not desired.
