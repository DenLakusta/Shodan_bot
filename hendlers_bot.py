import flask
import shodan
import telebot
from flask import request
from flask_sslify import SSLify
import requests
from telebot import types
import config_shodan
import os
import ip_whois
import jsonpickle
import json
import time
import re
import api_shodan


bot = telebot.AsyncTeleBot(config_shodan.token)


def hendler_base_ip(id, mess_req):
    # chat_id = data['message']['chat']['id']
    regexp_ip = r'\d.+'
    try:
        ip_re = re.findall(regexp_ip, mess_req)
        target = str(ip_re).strip("['']")
        text = api_shodan.return_result_ip(target)
        parts = parts_message(text)
        for part in parts:
            bot.send_message(id, part)
    except shodan.APIError as e:
        bot.send_message(id, e)
    except BaseException as error:
        print(str(error))


def hendler_base_host(id, mess_req):
    # chat_id = data['message']['chat']['id']
    regexp_hostname = r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]'
    host = re.search(regexp_hostname, mess_req.lower()).group()
    target = str(host)
    text = api_shodan.response_hostname(target)
    parts = parts_message(text)
    try:
        for part in parts:
            bot.send_message(id, part)
    except shodan.APIError as e:
        bot.send_message(id, e)
    except BaseException as error:
        bot.send_message(chat_id, error)


def hendler_related_ip(id, mess_req):
    # chat_id = data['message']['chat']['id']
    regexp_ip = r'\d.+'
    ip_re = re.findall(regexp_ip, mess_req)
    ip = str(ip_re).strip("['']")
    bot.send_message(id, 'Process can take some time')
    text = api_shodan.get_related_ip(ip)
    parts = parts_message(text)
    try:
        for part in parts:
            bot.send_message(id, part)
    except shodan.APIError as e:
        bot.send_message(id, e)
    except BaseException as error:
        bot.send_message(id, error)

def hendler_related_host(id, mess_req):
    # chat_id = data['message']['chat']['id']
    regexp_hostname = r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]'
    host = re.search(regexp_hostname, mess_req.lower()).group()
    target = str(host)
    bot.send_message(id, 'Process can take some time')
    text = api_shodan.get_related_hosts(target)
    parts = parts_message(text)
    try:
        for part in parts:
            bot.send_message(id, part)
    except shodan.APIError as e:
        bot.send_message(id, e)
    except BaseException as error:
        bot.send_message(id, error)


def hendler_vulns_ip(id, mess_req):

    # chat_id = data['message']['chat']['id']
    regexp_ip = r'\d.+'
    ip_re = re.findall(regexp_ip, mess_req)
    ip = str(ip_re).strip("['']")
    text = api_shodan.vulns_simple(ip)
    parts = parts_message_vulns(text)
    try:
        for part in parts:
            bot.send_message(id, part)
    except shodan.APIError as e:
        bot.send_message(id, e)
    except BaseException as error:
        bot.send_message(id, error)


def hendler_vulns_hostname(id, mess_req):
    # chat_id = data['message']['chat']['id']
    regexp_hostname = r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]'
    host = re.search(regexp_hostname, mess_req.lower()).group()
    target = str(host)
    ip = api_shodan.get_ip_from_host(target)
    text = api_shodan.vulns_simple(ip)
    parts = parts_message_vulns(text)
    try:
        for part in parts:
            bot.send_message(id, part)
    except shodan.APIError as e:
        bot.send_message(id, e)
    except BaseException as error:
        bot.send_message(id, error)


def hendler_full_info(id, mess_req):
    # chat_id = data['message']['chat']['id']
    regexp_ip = r'\d.+'
    regexp_hostname = r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]'
    if re.search(regexp_ip, mess_req):
        ip_re = re.findall(regexp_ip, mess_req)
        target = str(ip_re).strip("['']")
        text = api_shodan.full_info_ip(target)
        parts = parts_message(text)
        try:
            for part in parts:
                time.sleep(1)
                bot.send_message(id, part)
                time.sleep(2)
        except shodan.APIError as e:
            bot.send_message(id, e)
        except BaseException as error:
            bot.send_message(id, error)

    elif re.search(regexp_hostname, mess_req):
        host = re.search(regexp_hostname, mess_req.lower()).group()
        target = str(host)
        text = api_shodan.full_info_hostname(target)
        parts = parts_message(text)
        try:
            for part in parts:
                bot.send_message(id, part)
                time.sleep(2)
        except shodan.APIError as e:
            bot.send_message(id, e)
        except BaseException as error:
            bot.send_message(id, error)


def hendler_whois_ip(id, mess_req):
    # chat_id = data['message']['chat']['id']
    regexp_ip = r'\d.+'
    regexp_hostname = r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]'
    if re.search(regexp_ip, mess_req):
        ip_re = re.findall(regexp_ip, mess_req)
        target = str(ip_re).strip("['']")
        text = ip_whois.get_json_whois(target)
        bot.send_message(id, text)
    elif re.search(regexp_hostname, mess_req):
        #
        host = re.search(regexp_hostname, mess_req.lower()).group()
        hostname = str(host)
        # ip = api_shodan.get_ip_from_host(hostname)
        # target = str(ip).strip("['']")
        text = ip_whois.get_json_whois(hostname)
        bot.send_message(id, text)



def parts_message(text):
    MAX_MESSAGE_LENGTH = 4096
    parts = []
    # if len(text) >= MAX_MESSAGE_LENGTH:
    while len(text) > 0:
        if len(text) <= MAX_MESSAGE_LENGTH:
            parts.append(text)
            break

        elif len(text) > MAX_MESSAGE_LENGTH:
            part = text[:MAX_MESSAGE_LENGTH]
            first_lnbr = part.rfind('\n\n')
            parts.append(part[:first_lnbr])
            text = text[(first_lnbr):]
        else:
            parts.append(text)
            break
    return parts

def parts_message_vulns(text):
    MAX_MESSAGE_LENGTH = 4096
    parts = []

    # if len(text) >= MAX_MESSAGE_LENGTH:
    while len(text) > 0:
        if len(text) <= MAX_MESSAGE_LENGTH:
            parts.append(text)
            break

        elif len(text) > MAX_MESSAGE_LENGTH:
            part = text[:MAX_MESSAGE_LENGTH]
            first_lnbr = part.rfind('VULNERABILITY')
            parts.append(part[:first_lnbr])
            text = text[(first_lnbr):]
        else:
            parts.append(text)
            break
    return parts


def main():
    pass


if __name__ == '__main__':
    main()
