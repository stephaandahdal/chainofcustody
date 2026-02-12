#!/usr/bin/env python3

import os
import sys
import argparse
import struct
import hashlib
from datetime import datetime, timezone
from Crypto.Cipher import AES
BLOCK_STRUCT = struct.Struct("32s d 32s 32s 12s 12s 12s I") # given struct command

# Different states
STATE_INITIAL   = struct.pack("12s", b"INITIAL")
STATE_CHECKEDIN = struct.pack("12s", b"CHECKEDIN")
STATE_CHECKEDOUT= struct.pack("12s", b"CHECKEDOUT")
STATE_DISPOSED  = struct.pack("12s", b"DISPOSED")
STATE_DESTROYED = struct.pack("12s", b"DESTROYED")
STATE_RELEASED  = struct.pack("12s", b"RELEASED")


# Remove command options
VALID_REMOVE_REASONS = {
    "DISPOSED":  STATE_DISPOSED,
    "DESTROYED": STATE_DESTROYED,
    "RELEASED":  STATE_RELEASED,
}

# AES key string from document
AES_KEY = b"R0chLi4uLi4uLi4=" 

PWD_ENV_VARS = {
    "POLICE":"BCHOC_PASSWORD_POLICE",
    "LAWYER":"BCHOC_PASSWORD_LAWYER",
    "ANALYST": "BCHOC_PASSWORD_ANALYST",
    "EXECUTIVE":"BCHOC_PASSWORD_EXECUTIVE",
    "CREATOR": "BCHOC_PASSWORD_CREATOR",
}

FILE_PATH_ENV = "BCHOC_FILE_PATH"


# HELP FUNCTIONS
#CSE469 Chain of Custody (Track 1)
#Generative AI Used: ChatGPT (OpenAI, Dec 1, 2025)
#Purpose: Create helper functions which will be used in command functions
#Prompt: "Help me create helper functions for reading and writing the bloackchain inputs."

def chainPath():
    return os.environ.get(FILE_PATH_ENV, "blockchain.bin")

def readRaw():
    path = chainPath()
    if not os.path.exists(path):
        return []

    data = open(path, "rb").read()
    blocks = []
    off = 0

    while off < len(data):
        if off + BLOCK_STRUCT.size > len(data):
            print("> Error: Blockchain file is corrupted (incomplete header)", file=sys.stderr)
            sys.exit(1)
        
        header = data[off:off+BLOCK_STRUCT.size]
        try:
            (prev_hash, ts_float, enc_case, enc_item,
             state, creator, owner, dlen) = BLOCK_STRUCT.unpack(header)
        except struct.error:
            print("> Error: Blockchain file is corrupted (invalid header)", file=sys.stderr)
            sys.exit(1)
            
        off += BLOCK_STRUCT.size
        
        if off + dlen > len(data):
            print("> Error: Blockchain file is corrupted (incomplete data block)", file=sys.stderr)
            sys.exit(1)
            
        body = data[off:off+dlen]
        off += dlen

        blocks.append({
            "prev_hash": prev_hash,
            "ts": ts_float,
            "enc_case": enc_case,
            "enc_item": enc_item,
            "state": state,
            "creator": creator,
            "owner": owner,
            "data": body,
        })
    return blocks

def writeRaw(blocks):
    """Write all blocks back to disk (binary only, no JSON allowed). :contentReference[oaicite:10]{index=10}"""
    path = chainPath()
    out = []
    for b in blocks:
        header = BLOCK_STRUCT.pack(
            b["prev_hash"],
            b["ts"],
            b["enc_case"],
            b["enc_item"],
            b["state"],
            b["creator"],
            b["owner"],
            len(b["data"]),
        )
        out.append(header)
        out.append(b["data"])
    with open(path, "wb") as f:
        f.write(b"".join(out))

def currTime():
    return datetime.now(timezone.utc).timestamp() # UTC timezone according to document

def makeTimestamp(ts_float):
    # make timestamp according to document preference
    dt = datetime.fromtimestamp(ts_float, tz=timezone.utc)
    return dt.isoformat(timespec="microseconds").replace("+00:00", "Z")

def sha256Hash(b):
    packed = BLOCK_STRUCT.pack(
        b["prev_hash"],
        b["ts"],
        b["enc_case"],
        b["enc_item"],
        b["state"],
        b["creator"],
        b["owner"],
        len(b["data"]),
    ) + b["data"]
    return hashlib.sha256(packed).digest()

def pad12(txt):
    raw = txt.encode("utf-8")
    return raw.ljust(12, b"\x00")

# ENCRYPTION FUNCTIONS
#CSE469 Chain of Custody (Track 1)
#Generative AI Used: ChatGPT (OpenAI, Dec 1, 2025)
#Purpose: Make functions for encryption/decryption of information
#Prompt: "Create functions that allow me to encrypt/decrypt case ids, items, etc."

def encryptCaseId(uuid_str: str) -> bytes:
    uuid_clean = uuid_str.replace("-", "")
    uuid_bytes = bytes.fromhex(uuid_clean)

    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    encrypted = cipher.encrypt(uuid_bytes)

    return encrypted.hex().encode("ascii")

def encryptItemId(item_int: int) -> bytes:
    raw4 = int(item_int).to_bytes(4, "big")
    
    padded = raw4.rjust(16, b"\x00")
    
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    encrypted = cipher.encrypt(padded)
    
    return encrypted.hex().encode("ascii")

def decryptItemId(enc_bytes: bytes) -> int:
    hex_str = enc_bytes[:32].decode("ascii")
    ct = bytes.fromhex(hex_str)

    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    decrypted = cipher.decrypt(ct)

    return int.from_bytes(decrypted[-4:], "big")


def decryptCaseId(enc_bytes: bytes) -> str:
    ct = bytes.fromhex(enc_bytes[:32].decode("ascii"))

    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    decrypted = cipher.decrypt(ct)  # 16 bytes

    uuid_hex = decrypted.hex()
    return (
        f"{uuid_hex[:8]}-"
        f"{uuid_hex[8:12]}-"
        f"{uuid_hex[12:16]}-"
        f"{uuid_hex[16:20]}-"
        f"{uuid_hex[20:32]}"
    )


# PASSWORD FUNCTIONS
#CSE469 Chain of Custody (Track 1)
#Generative AI Used: ChatGPT (OpenAI, Dec 1, 2025)
#Purpose: Detect certain passwords necessary according to document
#Prompt: "Make password handler functions to check whether owner/creator password is valid."

def allPasswords():
    out = {}
    for role, envname in PWD_ENV_VARS.items():
        out[role] = os.environ.get(envname, "")
    return out

def isCreatorPassword(pw: str) -> bool:
    return pw == os.environ.get(PWD_ENV_VARS["CREATOR"], "")

def isOwnerPassword(pw: str) -> bool:
    pwset = set(allPasswords().values())
    return pw in pwset


# BLOCKCHAIN HELPER FUNCTIONS
#CSE469 Chain of Custody (Track 1)
#Generative AI Used: ChatGPT (OpenAI, Dec 1, 2025)
#Purpose: Before initializing blockchain, we need to have functions to link and create blocks
#Prompt: "Generate functions to ensure intial blocks, apppending blocks, and making sure block chaining is valid."

def ensureInitBlock():
    blocks = readRaw()
    if blocks:
        return blocks, False

    genesis = {
        "prev_hash": b"\x00"*32,
        "ts": 0.0,
        "enc_case": b"0"*32,
        "enc_item": b"0"*32,
        "state": STATE_INITIAL,
        "creator": b"\x00"*12,
        "owner": b"\x00"*12,
        "data": b"Initial block\x00",
    }

    writeRaw([genesis])
    return [genesis], True

def lastBlockForItem(blocks, enc_item):
    for b in reversed(blocks):
        if b["enc_item"] == enc_item:
            return b
    return None

def appendBlock(blocks, new_block):
    # Only the very first block (genesis) has a zero parent hash.
    # Every appended block should point to the hash of the current tip.
    if len(blocks) == 0:
        prev = b"\x00" * 32
    else:
        prev = sha256Hash(blocks[-1])

    new_block["prev_hash"] = prev
    blocks.append(new_block)
    writeRaw(blocks)
    return new_block

# COMMAND FUNCTIONS !!!!
#CSE469 Chain of Custody (Track 1)
#Generative AI Used: ChatGPT (OpenAI, Dec 1, 2025)
#Purpose: The main bulk of the code to create the functions used for every command.
#Prompt: "For the list of blockchain commands given, generate skeleton code for each command and other error checks."

def cmd_init():
    try:
        blocks, created = ensureInitBlock()
        if created:
            print("> Blockchain file not found. Created INITIAL block.")
        else:
            print("> Blockchain file found with INITIAL block.")
        return 0
    except SystemExit as e:
        return e.code if e.code else 1

def cmd_add(case_id, item_ids, creator_name, password):
    #Generative AI Used:ChatGPT (OpenAI, Nov 1st, 2025)
    #Purpose: Help me format code and understand how to add new block
    #Prompt: "Help make understand function and implementation"
    #also for command check in

    if not isCreatorPassword(password):
        print("> Invalid password")
        return 1

    blocks, _ = ensureInitBlock()

    for item in item_ids:
        e_item = encryptItemId(item)

        if lastBlockForItem(blocks, e_item) is not None:
            print("> Duplicate item id, cannot add again")
            return 1

        ts = currTime()
        new_block = {
            "prev_hash": b"",
            "ts": ts,
            "enc_case": encryptCaseId(case_id),
            "enc_item": e_item,
            "state": STATE_CHECKEDIN,
            "creator": pad12(creator_name),
            "owner": b"\x00" * 12, 
            "data": b"",
        }
        
        appendBlock(blocks, new_block)

        print(f"> Added item: {item}")
        print("> Status: CHECKEDIN")
        print(f"> Time of action: { makeTimestamp(ts) }")

    return 0

def cmd_checkout(item_id, password):
    if not isOwnerPassword(password):
        print("> Invalid password")
        return 1

    blocks, _ = ensureInitBlock()

    enc_item = encryptItemId(item_id)
    last = lastBlockForItem(blocks, enc_item)

    if last is None:
        print("> Item not found / not added")
        return 1
    
    last_state = last["state"].decode(errors="ignore").strip("\x00")

    if last_state in ("DISPOSED", "DESTROYED", "RELEASED"):
        print("> Item has been removed; cannot checkout")
        return 1

    if last_state != "CHECKEDIN":
        print("> Item not CHECKEDIN; cannot checkout")
        return 1
    ts = currTime()

    new_block = {
        "prev_hash": b"",
        "ts": ts,
        "enc_case": last["enc_case"],
        "enc_item": enc_item,
        "state": STATE_CHECKEDOUT,
        "creator": last["creator"],
        "owner": last["owner"],
        "data": b"",
    }
    appendBlock(blocks, new_block)

    print("> Case:", decryptCaseId(last["enc_case"]))
    print(f"> Checked out item: {item_id}")
    print("> Status: CHECKEDOUT")
    print(f"> Time of action: { makeTimestamp(ts) }")
    return 0

def cmd_checkin(item_id, password):
    if not isOwnerPassword(password):
        print("> Invalid password")
        return 1

    blocks, _ = ensureInitBlock()

    e_item = encryptItemId(item_id)
    last = lastBlockForItem(blocks, e_item)
    if last is None:
        print("> Item not found / not added")
        return 1

    last_state = last["state"].decode(errors="ignore").strip("\x00")
    if last_state in ("DISPOSED", "DESTROYED", "RELEASED"):
        print("> Item has been disposed, destroyed, or released: Cannot check in.")
        return 1
    if last_state == "CHECKEDIN":
        print("> Item already CHECKEDIN; cannot check in again")
        return 1
    
    ts = currTime()
    new_block = {
        "prev_hash": b"",
        "ts": ts,
        "enc_case": last["enc_case"],
        "enc_item": e_item,
        "state": STATE_CHECKEDIN,
        "creator": last["creator"],
        "owner": last["owner"],
        "data": b"",
    }
    appendBlock(blocks, new_block)

    print("> Case:", decryptCaseId(last["enc_case"]))
    print(f"> Checked in item: {item_id}")
    print("> Status: CHECKEDIN")
    print(f"> Time of action: { makeTimestamp(ts) }")
    return 0

def cmd_show_cases(password):
    authorized = isOwnerPassword(password)

    blocks = readRaw()
    cases_seen = set()
    for b in blocks:
        if b["enc_case"] == b"0"*32:
            continue
        if authorized:
            cases_seen.add(decryptCaseId(b["enc_case"]))
        else:
            cases_seen.add(b["enc_case"].hex())

    for c in sorted(cases_seen):
        print(c)

    return 0 if authorized else 1

def cmd_show_items(case_id, password):
    authorized = isOwnerPassword(password)
    blocks = readRaw()
    target = encryptCaseId(case_id)

    items = []
    for b in blocks:
        if b["enc_item"] == b"0"*32:
            continue
        if b["enc_case"] == target:
            if authorized:
                items.append(str(decryptItemId(b["enc_item"])))
            else:
                items.append(b["enc_item"].hex())

    for it in sorted(set(items)):
        print(it)

    return 0 if authorized else 1

def cmd_show_history(case_id, item_id, num_entries, reverse, password):
   
   authorized = isOwnerPassword(password)
   readBlock = readRaw()
   encode_case = encryptCaseId(case_id) if case_id else None
   enc_item = encryptItemId(item_id) if item_id is not None else None

   results = []
   for b in readBlock:
        if b["enc_item"] == b"0"*32 and b["enc_case"] == b"0"*32:
            continue

        if encode_case and b["enc_case"] != encode_case:
            continue
        if enc_item and b["enc_item"] != enc_item:
            continue
        results.append(b)
    
   if reverse:
         results.reverse()
    
   if num_entries is  not None:
       results = results[:num_entries]
    
   for b in results:
       state_str = b["state"].decode(errors ="ignore").strip("\x00")

       if authorized:
           case_out = decryptCaseId(b["enc_case"])
           item_out = str(decryptItemId(b["enc_item"]))
       else:
           case_out = b["enc_case"].hex()
           item_out = b["enc_item"].hex()
       
       print("> Case:", case_out)
       print("> Item:", item_out)
       print("> Action:", state_str)
       print("> Time:", makeTimestamp(b["ts"]))
       print(">")

   return 0 if authorized else 1

def cmd_remove(item_id, why, owner_info, password):
    # "remove": only creator password.
    # must currently be CHECKEDIN. After this, no more actions allowed on that item.
    # why must be DISPOSED / DESTROYED / RELEASED. If RELEASED, -o required. :contentReference[oaicite:22]{index=22}
    #Portions of the code in this project were generated with assistance from ChatGPT, an AI tool developed by OpenAI. 
    #Reference: OpenAI. (2025). ChatGPT [Large language model]. openai.com/chatgpt

    if not isCreatorPassword(password):
        print("> Invalid password")
        return 1

    why_up = why.upper()
    if why_up not in VALID_REMOVE_REASONS:
        print("> Invalid reason")
        return 1
    if why_up == "RELEASED" and not owner_info:
        print("> RELEASED requires owner information")
        return 1
    blocks, _ = ensureInitBlock()

    e_item = encryptItemId(item_id)
    last = lastBlockForItem(blocks, e_item)

    if last is None:
        print("> Item not found / not added")
        return 1

    last_state = last["state"].decode(errors="ignore").strip("\x00")
    if last_state != "CHECKEDIN":
        print("> Item not CHECKEDIN; cannot remove")
        return 1

    blob = why_up.encode("utf-8")
    if why_up == "RELEASED":
        blob += b"|" + owner_info.encode("utf-8")

    ts = currTime()

    new_block = {
        "prev_hash": b"", 
        "ts": ts,
        "enc_case": last["enc_case"],
        "enc_item": e_item,
        "state": VALID_REMOVE_REASONS[why_up],
        "creator": last["creator"],
        "owner": last["owner"],
        "data": blob,
    }

    appendBlock(blocks, new_block)
    return 0


def cmd_verify():
    blocks = readRaw()
    print("> Transactions in blockchain:", len(blocks))

    if len(blocks) == 0:
        print("> State of blockchain= error")
        print("> blocks not found")
        return 1

    first = blocks[0]
    if (first["prev_hash"] != b"\x00"*32 or 
        first["ts"] != 0.0 or 
        first["state"] != STATE_INITIAL):
        print("> State of blockchain: ERROR")
        print("> Bad block:", sha256Hash(first).hex())
        print("> Invalid initial block")
        return 1
    for i in range(1, len(blocks)):
        expected_prev = sha256Hash(blocks[i-1])
        if blocks[i]["prev_hash"] != expected_prev:
            print("> State of blockchain: ERROR")
            print("> Bad block:", sha256Hash(blocks[i]).hex())
            print("> Parent block: NOT FOUND")
            return 1
    #  no illegal sequences (checkout/checkin/remove rules)
    item_blocks = {}
    for i, b in enumerate(blocks):
        if b["enc_item"] == b"0"*32:
            continue
        e_item = b["enc_item"]
        state_str = b["state"].decode(errors="ignore").strip("\x00")
        if e_item not in item_blocks:
            item_blocks[e_item] = []
        item_blocks[e_item].append((state_str, i))

    
    for e_item, states in item_blocks.items():
        removed = False
        last = None
        for state, idx in states:
            b = blocks[idx]

            if removed: # after removing
                print("> State of blockchain: ERROR")
                print("> Bad block:", sha256Hash(b).hex())
                print("> Item checked out or checked in after removal from chain.")
                return 1
                
            if state == "CHECKEDOUT" and last == "CHECKEDOUT": #double check out
                print("> State of blockchain: ERROR")
                print("> Bad block:", sha256Hash(b).hex())
                print("> Double checkout")
                return 1
            if state == "CHECKEDIN" and last == "CHECKEDIN": # double check inn
                print("> State of blockchain: ERROR")
                print("> Bad block:", sha256Hash(b).hex())
                print("> Double checkin")
                return 1
            if state in ["DISPOSED", "DESTROYED", "RELEASED"]: # double remove
                if last in ["DISPOSED", "DESTROYED", "RELEASED"]:
                    print("> State of blockchain: ERROR")
                    print("> Bad block:", sha256Hash(b).hex())
                    print("> double removal")
                    return 1
                removed= True
            last = state
    # no duplicate parent hashes
    seen_parents ={}
    for i, b  in enumerate(blocks):
        if b["prev_hash"]== b"\x00"*32:
            continue
        if b["prev_hash"] in seen_parents:
            print("> State of blockchain: ERROR")
            print("> Bad block:", sha256Hash(b).hex())
            print("> Parent block:", b["prev_hash"].hex())
            print("> Two blocks were found with the same parent.")
            return 1
        seen_parents[b["prev_hash"]] = i
    print("> State of blockchain: CLEAN")
    return 0

def cmd_summary(case_id):

    blocks = readRaw()
    target = encryptCaseId(case_id)

    latest_state_for_item = {}
    for b in blocks:
        if b["enc_item"] == b"0"*32:
            continue
        if b["enc_case"] != target:
            continue
        state_str = b["state"].decode(errors="ignore").strip("\x00")
        latest_state_for_item[b["enc_item"]] = state_str

    counts = {
        "CHECKEDIN": 0,
        "CHECKEDOUT": 0,
        "DISPOSED": 0,
        "DESTROYED": 0,
        "RELEASED": 0,
    }
    for st in latest_state_for_item.values():
        if st in counts:
            counts[st] += 1

    print(f"Case summary for case ID: {case_id}")
    print(f"Total Evidence Items: {len(latest_state_for_item)}")
    print(f"Checked In: {counts['CHECKEDIN']}")
    print(f"Checked Out: {counts['CHECKEDOUT']}")
    print(f"Disposed: {counts['DISPOSED']}")
    print(f"Destroyed: {counts['DESTROYED']}")
    print(f"Released: {counts['RELEASED']}")

    return 0


# PARSE COMMAND LINE FUNCTIONS
#CSE469 Chain of Custody (Track 1)
#Generative AI Used: ChatGPT (OpenAI, Dec 1, 2025)
#Purpose: After making all command functions, we need to parse command input to be able read input and run them to functions.
#Prompt: "Help me parse command line input so that I can parse all arguments accordingly and pass taken input into command functions."

def cli_main():
    parser = argparse.ArgumentParser(prog="bchoc")
    sub = parser.add_subparsers(dest="cmd")

    # init
    sub.add_parser("init")

    # add
    p_add = sub.add_parser("add")
    p_add.add_argument("-c", "--case", dest="case_id", required=True)
    p_add.add_argument("-i", "--item", dest="item_ids", action="append", required=True, type=int)
    p_add.add_argument("-g", "--creator", dest="creator", required=True)
    p_add.add_argument("-p", "--password", dest="password", required=True)

    # checkout
    p_checkout = sub.add_parser("checkout")
    p_checkout.add_argument("-i", "--item", dest="item_id", required=True, type=int)
    p_checkout.add_argument("-p", "--password", dest="password", required=True)

    # checkin
    p_checkin = sub.add_parser("checkin")
    p_checkin.add_argument("-i", "--item", dest="item_id", required=True, type=int)
    p_checkin.add_argument("-p", "--password", dest="password", required=True)

    # show
    p_show = sub.add_parser("show")
    show_sub = p_show.add_subparsers(dest="showcmd")

    p_show_cases = show_sub.add_parser("cases")
    p_show_cases.add_argument("-p", "--password", dest="password", required=False, default="")

    p_show_items = show_sub.add_parser("items")
    p_show_items.add_argument("-c", "--case", dest="case_id", required=True)
    p_show_items.add_argument("-p", "--password", dest="password", required=False, default="")

    p_show_hist = show_sub.add_parser("history")
    p_show_hist.add_argument("-c", "--case", dest="case_id", required=False)
    p_show_hist.add_argument("-i", "--item", dest="item_id", required=False, type=int)
    p_show_hist.add_argument("-n", dest="num_entries", required=False, type=int)
    p_show_hist.add_argument("-r", "--reverse", dest="reverse", action="store_true")
    p_show_hist.add_argument("-p", "--password", dest="password", required=False, default="")

    # remove
    p_remove = sub.add_parser("remove")
    p_remove.add_argument("-i", "--item", dest="item_id", required=True, type=int)
    p_remove.add_argument("-y", "--why", dest="why", required=True)
    p_remove.add_argument("-o", "--owner", dest="owner_info", required=False)
    p_remove.add_argument("-p", "--password", dest="password", required=True)

    # verify
    sub.add_parser("verify")

    # summary
    p_summary = sub.add_parser("summary")
    p_summary.add_argument("-c", "--case", dest="case_id", required=True)

    args = parser.parse_args()

    if args.cmd == "show" and args.showcmd is None:
        parser.print_help()
        return 2

    if args.cmd == "init":
        return cmd_init()

    if args.cmd == "add":
        return cmd_add(args.case_id, args.item_ids, args.creator, args.password)

    if args.cmd == "checkout":
        return cmd_checkout(args.item_id, args.password)

    if args.cmd == "checkin":
        return cmd_checkin(args.item_id, args.password)

    if args.cmd == "show":
        if args.showcmd == "cases":
            return cmd_show_cases(args.password)
        if args.showcmd == "items":
            return cmd_show_items(args.case_id, args.password)
        if args.showcmd == "history":
            return cmd_show_history(
                case_id=args.case_id,
                item_id=args.item_id,
                num_entries=args.num_entries,
                reverse=args.reverse,
                password=args.password,
            )

    if args.cmd == "remove":
        return cmd_remove(args.item_id, args.why, args.owner_info, args.password)

    if args.cmd == "verify":
        return cmd_verify()

    if args.cmd == "summary":
        return cmd_summary(args.case_id)

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(cli_main())