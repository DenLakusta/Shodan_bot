import psycopg2

DB_NAME = 'dehkm676okscod'
DB_USER = 'wvncwlowheccpz'
DB_PASS = '7741122fa3b0778a69858fc2427c6dff6365faffd630b1e8d0d58a7e892200d1'
DB_HOST = 'ec2-54-243-241-62.compute-1.amazonaws.com'
DB_PORT = '5432'



def create_table():

    commands = '''CREATE TABLE db_shodbot
          (ID INT PRIMARY KEY     NOT NULL,
          USER_ID        INT    NOT NULL,
          USER_NAME      VARCHAR(50)  NOT NULL,
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
    try:


        USER_ID = message.from_user.id
        USER_NAME = message.from_user.username
        LAST_MESSAGE = message.text

        insert_query = ("INSERT INTO db_shodbot (USER_ID, USER_NAME, LAST_MESSAGE) VALUES(%s, %s, %s)")
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

        mess_query = ("SELECT user_id, last_message FROM bot_db WHERE user_id = %s")
        cur.execute(mess_query, (id,))
        mess = cur.fetchall()
        mess_req = mess[-1][-1]
        mess_id = mess[-1][0]
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
