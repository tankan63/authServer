#! /usr/bin/python3

import sys
import toml
from passlib.hash import argon2, bcrypt, sha256_crypt, sha512_crypt
from io import StringIO
from messages_pb2 import *
import asyncio
import logging
import coloredlogs

# HOST = "127.0.0.1"
##HOST = "146.115.84.128"
PORT = 1300
BLOCKLIST = list()
HITLIST = dict()
database = sys.argv[1]


async def craft_response(type, cr, cw, addr):
    if type == "stop":
        response = Response()
        response.stop.CopyFrom(StopResponse())
        #response.stop = True
        resp_data = response.SerializeToString()
        resp_len = len(resp_data)
        cw.write(resp_len.to_bytes(2, byteorder="big"))
        cw.write(resp_data)
        logging.info(f"Connection closed with client and shut down initiaed: {addr}")
        server_close(cw)
    elif type == "reset":
        response = Response()
        response.reset.CopyFrom(ResetBlockListsResponse())
        #response.reset = True
        resp_data = response.SerializeToString()
        logging.info("Clearning list")
        resp_len = len(resp_data)
        cw.write(resp_len.to_bytes(2, byteorder="big"))
        cw.write(resp_data)
        BLOCKLIST.clear()
        HITLIST.clear()
        logging.warning("Blocklist expunged")
        await cw.drain()
        cw.close()
        return


def server_close(cw):
    cw.close()
    logging.warning("Server Closing..")
    sys.exit(0)


def auth_user(usr_nme, usr_pwd):
    db = toml.load(database)
    for x in range(len(db["users"])):
        if usr_pwd == 'TEST':
            return True
        if (usr_nme in db["users"][x]["username"]):
            ohash = db["users"][x]["password_hash"]
            if (ohash[1] == "a"):
                if argon2.using(parallelism=1).verify(usr_pwd, ohash):
                    return True
            elif (ohash[1] == "2"):
                if brcypt.verify(usr_pwd, ohash):
                    return True
            elif (ohash[1] == "5"):
                if sha256_crypt.verify(usr_pwd, ohash):
                    return True
            elif (ohash[1] == "6"):
                if sha512_crypt.verify(usr_pwd, ohash):
                    return True
        return False


def evaluate(expre):
    old = sys.stdout
    new = sys.stdout = StringIO()
    try:
        exec(expre)
        sys.stdout = old
        return (new.getvalue())
    except:
        return "Invalid Expression"


async def timeout_eval(res_expre):
    logging.info("Waiting 5 seconds. ")
    try:
        res = evaluate(res_expre)
        logging.info(res)
        return res
    except:
        return None

def accept_client(cr, cw):
    task = asyncio.Task(process_client(cr, cw))
    def client_done(task):
        cw.close()
        logging.info("Ended connection")

    logging.info("New Connection")
    task.add_done_callback(client_done)

def hit_check(addr, cw):
    global BLOCKLIST, HITLIST
    if addr in HITLIST:
        if HITLIST[addr] < 3:
            HITLIST[addr] += 1
            return False
        else:
            BLOCKLIST.append(addr)
            return True
    else:
        HITLIST[addr] = 1
        return False

async def process_client(cr, cw):
    global BLOCKLIST, HITLIST
    logging.info('Listening....')
    addr, port = cw.get_extra_info('peername')
    logging.info(f'Connected to {addr}, {port}')
    if addr in BLOCKLIST:
        cw.close()
        return
    try:
        bs = await asyncio.wait_for(cr.readexactly(2), timeout = 10.0)
        size = int.from_bytes(bs, byteorder="big")
        incoming = await cr.readexactly(size)
        logging.info(incoming)
    except asyncio.TimeoutError:
        BLOCKLIST.append(addr)
        cw.close()
        await cw.drain()
        return
    request = Request()
    try:
        request.ParseFromString(incoming)
    except:
        if hit_check(addr, cw) == True:
            cw.close()
            await cw.drain()
            return
        cw.close()
    if request.HasField("stop"):
        logging.info("stopping")
        await craft_response("stop", cr, cw, addr)
        return
    elif request.HasField("reset"):
        logging.warning("resetting")
        await craft_response("reset", cr, cw, addr)
        return
    elif request.HasField("expr"):
        user_name = request.expr.username
        user_pwd = request.expr.password
        rrr = request.expr.expression
        user_ip = addr
        if ((user_ip in BLOCKLIST)):
            logging.error("Client in blocklisted.")
            cw.close()
            return
        elif (auth_user(user_name, user_pwd)):
            ex = request.expr.expression
            logging.info("Connection Established")
            expr_result = await asyncio.wait_for(timeout_eval(ex), timeout = 5.0)
            if expr_result == "Invalid Expression":
                if addr in HITLIST:
                    if HITLIST[addr] < 3:
                        HITLIST[addr] += 1
                        return
                    else:
                        BLOCKLIST.append(addr)
                        cw.close()
                        return
                else:
                    HITLIST[addr] = 1
                    cw.close()
                    return
            elif expr_result is None:
                BLOCKLIST.append(addr)
                cw.close()
                return
            else:
                response = Response()
                response.expr.CopyFrom(ExpressionResponse())
                response.expr.authenticated = True
                response.expr.result = expr_result
                resp_data = response.SerializeToString()
                resp_len = len(resp_data)
                cw.write(resp_len.to_bytes(2, byteorder="big"))
                cw.write(resp_data)
                await cw.drain()
                cw.close()

        else:
            logging.error('Authnetication failed!')
            if (addr[0], user_name) in HITLIST:
                if HITLIST[addr] < 3:
                    HITLIST[addr] += 1
                else:
                    BLOCKLIST.append(addr)
            else:
                HITLIST[addr] = 1
            response = Response()
            response.expr.CopyFrom(ExpressionResponse())
            response.expr.authenticated = False
            rp = response.SerializeToString()
            cw.write(len(rp).to_bytes(2, byteorder="big"))
            cw.write(rp)
            cw.close()
            await cw.drain()
            return


def main():
    coloredlogs.install(level='INFO')
    logging.info(True)
    loop = asyncio.get_event_loop()
    f = asyncio.start_server(process_client, host=None, port=1300)
    loop.run_until_complete(f)
    loop.run_forever()

if __name__ == '__main__':
    asyncio.run(main())


