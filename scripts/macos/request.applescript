on Receive()
    tell application "Mail" to activate
    tell application "Mail" to check for new mail in "Monitor"
end Receive

on Reset()
    tell application "Mail"
        quit
        open
    end tell
end Reset
