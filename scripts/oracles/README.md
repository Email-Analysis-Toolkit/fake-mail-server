# The Empty Line Oracle

Present in iOS Mail version below 16.4. Format oracle allowing decryption S/MIME emails block by block.

Format oracle works as follows:
0. i = 1
1. Download Part i of a multipart/mixed mail.
2. Decrypt
3. Empty Line (`\n\n`) in decryption?
    3.1. Yes: i++; Goto 1.
    3.2. No: Goto 4
4. Close Connection/stop downloading mail

# Setup
0. Install mkcert if you have not and create a CA.
1. Create an S/MIME certificate and an S/MIME encrypted email: `./create_smime_cert_and_mail.sh
   hex.mail` (for the simple hex character email)
2. Install the generated `smime.p12` certificate on the test device.

# Running the simulation
1. `cargo run --release loop-test all imap testcases/imap/oracles.ron`
2. In another terminal:
    `python3 server.py [smime_mail]`
3. In another terminal:
    `python3 empty_line_sim.py`

# Running on an iPhone
1. `cargo run --release loop-test all imap testcases/imap/oracles.ron`
2. In another terminal:
    `python3 server.py [smime_mail]`
3. Set auto lock on iPhone to never (don't forget to reset ;-) )

`[smime_mail]` should only contain the base64 body of the S/MIME message.
    
# Scenarios
Scenarios can be tested by changing the init parameters of the `EmptyLineOracleGenerator` and the `SYMBOLS` constant.
## Sequential Queries (Passive MitM against TLS simulation)
Set `sequential=True`.

## Malicious IMAP 
1. Set `sequential=False`.
2. Play with the `alphabet_split` and `switch_to` parameters. Setting both to 16 seems to give good results for ASCII. 16/8 works good for Hex.

## ASCII
Set `SYMBOLS=ASCII_SYMBOLS`.

## Hex
Set `SYMBOLS=HEX_SYMBOLS`.

# Parameter explanations
* `SYMBOLS` what values can the bytes in the block take? (E.g., 7-Bit ASCII, Hex, BASE64, ...)
* `alphabet_split` into how many queries should the alphabet be split at each step?
* `switch_to` into how many queries should the alphabet be split after guessing the first two bytes.
* `sequential` should the generator wait (within reason) for each query to finish before sending the next one? This is what a MitM would need to do
    since they cannot differentiate between different emails. It's of course much faster not to do it.

# How does the search work?
It's essentially divide and conquer. If you use `alphabet_split=2` it's a binary search.

Example for binary search (`x`` means query was correct):
```
                                                        {00..ff}
                                                       x/      \
                                                    {00..7f}  {80..ff}
                                                   x/      \
                                                {00..3f}    ...
```

If we get two/more correct queries -- which might happen due to inaccuracy or because we managed to hight \n\n by chance on one of the garbage block -- we just keep all of them and perform our divide and conquer search on the sub queries until (hopefully) just one alphabet containing a single symbol remains.

Luckily, false-negatives do not happen with iOS Mail (haven't seen one in all my tests), so we need to do no backtracking.
