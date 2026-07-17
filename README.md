# OffsetFinder

A OffsetFinder that gets Gameserver and Redirect offsets.

Inject the DLL into Fortnite and it'll scan for signatures, then dumps `GameserverOffsets-<Version>.h` or `RedirectOffsets-<Version>.h` 

## Missing Offsets 

Missing offsets just get skipped in the header. You'll still see them logged in the console as misses.

## Credits

Credits to Erbium, Starfall, Tellurium for using their signature patterns for this OffsetFinder
