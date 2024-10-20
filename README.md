# 🔥🔥 UPDATE 🔥🔥
1. NOW AUTO SOLVES CAPTCHA
2. CONCURRENT SESSION HANDLING

# 🔥🔥 MUST USE PYTHON 3.11.5 (CAPTCHA VERSION DOESNT WORK ON TERMUX)🔥🔥

## Features  
| Feature                                                     | Supported  |
|---------------------------------------------------------------|:----------------:|
| Concurrent session handling with async                        |        ✅        |
| Proxy binding to session                                       |        ✅        |
| Auto ref                                                      |        ✅        |
| Auto checkin                                                  |        ✅        |
| Auto play game                                                |        ✅        |
| Auto solve captcha                                             |        ✅        |
| Support for pyrogram .session                                 |        ✅        |
| Auto claim points each game                             |        ✅        |

## [Settings](https://github.com/datboycode/moonbixBot/blob/main/.env-example)
| Settings | Description |
|----------------------------|:-------------------------------------------------------------------------------------------------------------:|
| **API_ID / API_HASH**      | Platform data from which to run the Telegram session (default - android)                                      |       
| **REF_LINK**               | Put your ref link here (default: my ref link)                                                                 |
| **AUTO_TASK**              | Auto do task (default: True)                                                                                  |
| **AUTO_PLAY_GAME**         | AUTO PLAY GAME (default: True)                                                                                |
| **MORE_ACCURATE_CAPTCHA_SOLVER**         | Option to use more accurate solver (slight slower) (default: True)                              |
| **DELAY_EACH_ACCOUNT**         | SLEEP between each account (default: [15,25])                                                             |
| **USE_PROXY_FROM_FILE**    | Whether to use a proxy from the bot/config/proxies.txt file (True / False)                                    |


## Quick Start 📚

To install libraries and run bot - open run.bat on Windows

## Prerequisites
Before you begin, make sure you have the following installed:
- [Python](https://www.python.org/downloads/) **version 3.11.5**

## Obtaining API Keys
1. Go to my.telegram.org and log in using your phone number.
2. Select "API development tools" and fill out the form to register a new application.
3. Record the API_ID and API_HASH provided after registering your application in the .env file.

## Installation

# Linux manual installation
```shell
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
cp .env-example .env
nano .env  # Here you must specify your API_ID and API_HASH, the rest is taken by default
python3 main.py
```

You can also use arguments for quick start, for example:
```shell
~/moonbixBot >>> python3 main.py --action (1/2)
# Or
~/moonbixBot >>> python3 main.py -a (1/2)

# 1 - Run clicker
# 2 - Creates a session
```

# Windows manual installation
```shell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env-example .env
# Here you must specify your API_ID and API_HASH, the rest is taken by default
python main.py
```
You can also use arguments for quick start, for example:
```shell
~/moonbixBot >>> python main.py --action (1/2)
# Or
~/moonbixBot >>> python main.py -a (1/2)

# 1 - Run clicker
# 2 - Creates a session
```

# Termux manual installation
```
> pkg update && pkg upgrade -y
> pkg install python rust git -y
> git clone https://github.com/datboycode/moonbixBot.git
> cd moonbixBot
> pip install -r requirements.txt
> python main.py
```

You can also use arguments for quick start, for example:
```termux
~/moonbixBot > python main.py --action (1/2)
# Or
~/moonbixBot > python main.py -a (1/2)

# 1 - Run clicker
# 2 - Creates a session 
```
