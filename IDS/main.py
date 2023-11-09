import os
import base64
from scapy.all import sniff, IP, TCP, Raw
from mysql.connector import pooling, Error
import logging
from dotenv import load_dotenv
import signal
import sys
from collections import defaultdict
from datetime import datetime, timedelta

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(filename='ids_log.log', level=logging.INFO,
                    format='%(asctime)s:%(levelname)s:%(message)s')

# Database connection pool
db_config = {
    'host': 'localhost',
    'database': 'ids_logs',
    'user': os.getenv('MYSQL_USER'),
    'password': os.getenv('MYSQL_PASSWORD')
}

try:
    pool = pooling.MySQLConnectionPool(pool_name="mypool",
                                       pool_size=5,
                                       pool_reset_session=True,
                                       **db_config)
except Error as e:
    logging.error(f"Error creating a connection pool: {e}")
    sys.exit(1)


# Signal handler for graceful shutdown
def signal_handler(sig, frame):
    logging.info('Interrupt received, shutting down ...')
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


# Function to clear all traffic logs
def clear_traffic_logs():
    try:
        connection = pool.get_connection()
        cursor = connection.cursor()
        cursor.execute("TRUNCATE TABLE traffic_logs;")
        connection.commit()
        logging.info("Cleared all traffic logs.")
    except Error as e:
        logging.error(f"Error clearing traffic logs: {e}")
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# Intrusion detection logic
PORT_SCAN_THRESHOLD_COUNT = 100  # Number of connection attempts
PORT_SCAN_THRESHOLD_TIME = timedelta(seconds=10)  # Time frame for counting connection attempts
recent_connections = defaultdict(list)


def detect_port_scan(src_ip, dst_port, current_time):
    # Remove old entries
    recent_connections[src_ip] = [
        time for time in recent_connections[src_ip] if current_time - time < PORT_SCAN_THRESHOLD_TIME
    ]
    # Add new entry
    recent_connections[src_ip].append(current_time)
    # Check if threshold is exceeded
    if len(recent_connections[src_ip]) > PORT_SCAN_THRESHOLD_COUNT:
        return True
    return False


# Function to process packets
def process_packet(packet):
    try:
        connection = pool.get_connection()
        cursor = connection.cursor(prepared=True)

        src_ip = packet[IP].src if IP in packet else 'N/A'
        dst_ip = packet[IP].dst if IP in packet else 'N/A'
        protocol = packet.sprintf("%IP.proto%") if IP in packet else 'N/A'
        dst_port = packet[TCP].dport if TCP in packet else 'N/A'
        payload = base64.b64encode(packet[Raw].load).decode() if Raw in packet else None

        current_time = datetime.now()
        alert = detect_port_scan(src_ip, dst_port, current_time)

        insert_stmt = """INSERT INTO traffic_logs (src_ip, dst_ip, protocol, payload, alert)
                         VALUES (%s, %s, %s, %s, %s)"""
        data = (src_ip, dst_ip, protocol, payload, alert)

        cursor.execute(insert_stmt, data)
        connection.commit()

        if alert:
            logging.warning(f"Potential port scan detected from {src_ip}")

    except Error as e:
        logging.error(f"Database error: {e}")
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()


# Uncomment the next line to clear all traffic logs before starting the sniffing process
#clear_traffic_logs()

# Start sniffing the network
sniff(prn=process_packet, store=False)
