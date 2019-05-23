import flask
import shodan
import telebot
from flask import request
from flask_sslify import SSLify
import requests
from telebot import types
import config_shodan
import psycopg2
from telebot import TeleBot
import json
import time
import re
import api_shodan
import hendlers_bot
import jsonpickle
import ujson
from bd_in import *
# #


app = flask.Flask(__name__)


sslify = SSLify(app)
bot = telebot.TeleBot(config_shodan.token, threaded=True)

#
# def write_json(data, filename):
#     with open(filename, 'w') as f:
#         json.dump(data, f, indent=2, ensure_ascii=False)
#
# def write_target(text, chat_id):
#     write_json(text, filename='{}.json'.format(chat_id))


user_markup = telebot.types.ReplyKeyboardMarkup(True, False)
user_markup.add('help', 'base info', 'vulns', 'related hosts', 'full info', 'whois info')


@bot.message_handler(regexp = r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]')
@bot.message_handler(regexp = r'\d.+')
def hendle_first_request(message):
    regexp_ip = r'\d.+'
    mess_text = message.text
    ip_re = re.findall(regexp_ip, mess_text)
    ip = str(ip_re).strip("['']")
    if ip.split('.')[0] == '192' and ip.split('.')[1] == '168' or ip.split('.')[0] == '172' and ip.split('.')[1] == '76' or ip.split('.')[0] == '10' and ip.split('.')[1] == '10' or ip == '127.0.0.1' or ip == '0.0.0.0':
        bot.send_message(message.from_user.id, '\nYOU ENTER PRIVAT IP! PLEASE ENTER PUBLIC IP TO GET WRITE INFORMATION')
    else:
        insert_data(message)
        bot.send_message(message.from_user.id, '\nCHOSE ACTION', reply_markup=user_markup)



@bot.message_handler(commands=['start'])
def handle_start(message):
    text = 'WELCOME TO SHODAN BOT\nAT THE MOMENT BOT ARE WORKING IN TEST MODE. IF IT RETURN WRONG INFO OR YOU FIND SOME BUGS, PLEASE GIVE A FEEDBACK TO EMAIL shodanbot@protonmail.com\nJUST ENTER VALID IP OR HOSTNAME!\nFOR MORE INFORMATION ENTER\n"/help"'

    bot.send_message(message.from_user.id, text, reply_markup=user_markup)
    time.sleep(0.5)
    bot.send_message(message.from_user.id, '\nCHOSE ACTION', reply_markup=user_markup)


@bot.message_handler(commands=['help'])
@bot.message_handler(func=lambda mess: "help" == mess.text, content_types=['text'])
def handle_help(message):

    text = 'bse info - show base information about host\n\nvulns - show all vulnerabilities of the host and exploits, if they exists\n\nrelated hosts - show all hosts which are related with target by DNS\n\nfull info - show all information including "base info", "vulnerabilities" and "related hosts". You should know - using this command, BOT need some time to collect all information.\n\nwhois info - show information about host if there is no info in Shodan\n\nYou just need to enter valid IP (without port number) or HOSTNAME\n\nMost effective way to enter HOSTNAME is "exemple.com"(without protocol)'
    bot.send_message(message.from_user.id, text, reply_markup=user_markup)


@bot.message_handler(func=lambda mess: "base info" == mess.text, content_types=['text'])
def handle_base_info(message):
    regexp_hostname = r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]'
    regexp_ip = r'\d.+'
    id = str(message.chat.id)
    # print(id)
    data = request_query(id)
    # print(data)
    # path = '{}.json'.format(message.chat.id)
    # with open(path, 'r') as f:
    #     data = json.load(f)
    #     print(data)
    send_id = data[1]
    # print(send_id)
    text = data[0]
    # print(text)
    if re.search(regexp_ip, text):
        hendlers_bot.hendler_base_ip(send_id, text)
    elif re.search(regexp_hostname, text):
        hendlers_bot.hendler_base_host(send_id, text)

@bot.message_handler(func=lambda mess: "vulns" == mess.text, content_types=['text'])
def hendler_vulns(message):
    regexp_hostname = r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]'
    regexp_ip = r'\d.+'
    id = str(message.chat.id)
    # print(id)
    data = request_query(id)
    # print(data)
    send_id = data[1]
    # print(send_id)
    text = data[0]
    # print(text)
    if re.search(regexp_ip, text):
        hendlers_bot.hendler_vulns_ip(send_id, text)
    elif re.search(regexp_hostname, text):
        hendlers_bot.hendler_vulns_hostname(send_id, text)



@bot.message_handler(func=lambda mess: "related hosts" == mess.text, content_types=['text'])
def handle_related(message):
    regexp_hostname = r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]'
    regexp_ip = r'\d.+'
    id = str(message.chat.id)
    # print(id)
    data = request_query(id)
    # print(data)
    send_id = data[1]
    # print(send_id)
    text = data[0]
    # print(text)
    if re.search(regexp_ip, text):
       hendlers_bot.hendler_related_ip(send_id, text)
    elif re.search(regexp_hostname, text):
        hendlers_bot.hendler_related_host(send_id, text)


@bot.message_handler(func=lambda mess: "full info" == mess.text, content_types=['text'])
def handle_full(message):
    bot.send_message(message.chat.id, 'Process can take long time. If bot does not return correct or full information, maybe its sending too many requests and ShodanAPI cuold not process it. Try to collect information separately using buttons step by step')
    id = str(message.chat.id)
    # print(id)
    data = request_query(id)
    # print(data)
    send_id = data[1]
    # print(send_id)
    text = data[0]
    # print(text)
    hendlers_bot.hendler_full_info(send_id, text)


@bot.message_handler(func=lambda mess: "whois info" == mess.text, content_types=['text'])
def handle_whois(message):
    id = str(message.chat.id)
    # print(id)
    data = request_query(id)
    # print(data)
    send_id = data[1]
    print(send_id)
    text = data[0]
    print(text)
    hendlers_bot.hendler_whois_ip(send_id, text)


@app.route('/', methods=['POST'])
def get_message():
    # r = request.get_json()
    # chat_id = r['message']['chat']['id']
    # regexp_hostname = r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]'
    # regexp_ip = r'\d.+'
    # if re.search(regexp_ip, r['message']['text']) or re.search(regexp_hostname, r['message']['text']):
        # write_target(r, chat_id)

    json_string = flask.request.get_data().decode("utf-8")
    update = telebot.types.Update.de_json(json_string)
    bot.process_new_updates([update])
    return 'ok', 200


@app.route("/")
def web_hook():
    bot.remove_webhook()
    bot.set_webhook(url="https://{}.herokuapp.com".format(config_shodan.APP_NAME))
    return "CONNECTED", 200


def main():
    pass


if __name__ == '__main__':
    app.run()
