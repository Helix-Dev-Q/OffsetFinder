# OffsetFinder

A OffsetFinder that gets Gameserver and Redirect offsets.

Inject the DLL into Fortnite and it'll scan for signatures, then dumps `GameserverOffsets-<Version>.h` or `RedirectOffsets-<Version>.h` (it shows on the console as well and also copys the offsets to your clipboard)

## Missing Offsets 

Missing offsets just get skipped in the header. You'll still see them logged in the console as misses.

## Wrong Offsets

if the offsets that were generated/found may be wrong sometime like, 28.01 offsets some of them are wrong

## Credits

Credits to Erbium, Starfall, Tellurium for using their signature patterns for this OffsetFinder

## Example

Gameserver Offset dump [example](https://github.com/Helix-Dev-Q/random-stuff-for-my-repos/raw/refs/heads/main/Screen%20Recording%202026-07-17%20151438.mp4?raw=true)

Redirect Offset dump [example2](https://github.com/Helix-Dev-Q/random-stuff-for-my-repos/blob/main/Screenshot%202026-07-17%20151811.png?raw=true)
