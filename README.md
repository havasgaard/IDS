# Intrusion Detection System (IDS) using Python

## Table of Contents
- [Introduction](#introduction)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Customization](#customization)
- [Contributing](#contributing)
- [License](#license)

## Introduction

This Intrusion Detection System (IDS) is a Python-based network security tool designed to monitor network traffic and detect potential port scans. It utilizes the Scapy library for packet sniffing and MySQL for storing and analyzing traffic logs.

The IDS is capable of identifying suspicious network activity and generating alerts when certain threshold conditions are met. It's a valuable tool for enhancing the security posture of your network.

**Please note that this project is developed by a student who is still learning both cybersecurity and Python. Contributions and feedback are welcome as part of the learning process.**

## Prerequisites

Before you begin, make sure you have the following prerequisites installed:

- Python 3.x
- [Scapy](https://scapy.net/)
- [mysql-connector-python](https://dev.mysql.com/doc/connector-python/en/)
- [dotenv](https://pypi.org/project/python-dotenv/)

You also need access to a MySQL database for storing traffic logs.

## Installation

1. Clone this repository to your local machine:

    ```bash
    git clone https://github.com/havasgaard/IDS.git
    ```

2. Install the required Python libraries using pip:

    ```bash
    pip install scapy mysql-connector-python python-dotenv
    ```

3. Set up your MySQL database and provide the necessary connection details in a `.env` file. You can use the `.env.example` file as a template.

4. Uncomment the following line in the `main.py` file to clear all traffic logs (optional):

    ```python
    #clear_traffic_logs()
    ```

5. Start the IDS by running:

    ```bash
    python main.py
    ```

## Usage

The IDS will start sniffing network traffic and storing logs in your MySQL database. It will also generate alerts when potential port scans are detected.

You can view the logs and alerts in the MySQL database for further analysis.

## Configuration

You can configure the IDS by modifying the `main.py` file. Here are some key configurations:

- Database connection settings (host, user, password) in the `db_config` dictionary.
- Port scan detection thresholds (`PORT_SCAN_THRESHOLD_COUNT` and `PORT_SCAN_THRESHOLD_TIME`).
- Logging settings in the `logging.basicConfig` section.

## Customization

Feel free to customize and extend this IDS according to your specific requirements. You can add more sophisticated intrusion detection logic or integrate it with other security tools and services.

## Contributing

Contributions are welcome! If you have any ideas, bug reports, or feature requests, please open an issue or submit a pull request.
