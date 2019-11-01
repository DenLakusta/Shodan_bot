import psycopg2
import config_shodan
DB_NAME = config_shodan.DB_NAME
DB_USER = config_shodan.DB_USER
DB_PASS = config_shodan.DB_PASS
DB_HOST = config_shodan.DB_HOST
DB_PORT = config_shodan.DB_PORT


def create_table():
    commands = '''CREATE TABLE db_shodbot
          (ID            SERIAL  PRIMARY KEY ,
          USER_ID        INT    NOT NULL,
          USER_NAME      VARCHAR(50),
          MESSAGE        TEXT);'''
    conn = None
    try:
        conn = psycopg2.connect(database=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT)
        cur = conn.cursor()
    # for command in commands:
        cur.execute(commands)
        conn.commit()
        conn.close()
        print("Table created successfully")
    except (Exception, psycopg2.DatabaseError) as error:
        print(error)
    finally:
        if conn is not None:
            conn.close()


def insert_data(message):
    conn = psycopg2.connect(database=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT)
    cur = conn.cursor()
    USER_ID = message.from_user.id
    print(USER_ID)
    USER_NAME = message.from_user.first_name
    print(USER_NAME)
    LAST_MESSAGE = message.text
    print(LAST_MESSAGE)
    try:
        insert_query = ("INSERT INTO db_shodbot (USER_ID, USER_NAME, MESSAGE) VALUES(%s, %s, %s)")
        cur.execute(insert_query, (USER_ID, USER_NAME, LAST_MESSAGE))
        conn.commit()
        count = cur.rowcount
        print(count, "Record seccessfull")
    except (Exception, psycopg2.Error) as error:
        if (conn):
            print("Failed to insert record into mobile table", error)
    finally:
        # closing database connection.
        if (conn):
            cur.close()
            conn.close()
            print("PostgreSQL connection is closed")



def request_query(id):
    conn = psycopg2.connect(database=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT)
    cur = conn.cursor()
    try:
        mess_query = ("SELECT user_id, message FROM db_shodbot WHERE user_id = %s")
        cur.execute(mess_query, (id,))
        mess = cur.fetchall()
        # if len(mess) > 1:
        mess_req = mess[-1][-1]
        mess_id = mess[-1][0]
        # else:
        #     mess_req = mess[-1]
        #     mess_id = [0]
        return mess_req, mess_id

    except (Exception, psycopg2.Error) as error:
        if (conn):
            print("Failed to insert record into mobile table", error)
    finally:
        # closing database connection.
        if (conn):
            cur.close()
            conn.close()
            print("PostgreSQL connection is closed")


if __name__ == '__main__':
    create_table()
