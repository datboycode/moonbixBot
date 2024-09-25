import asyncio
import binascii
import json
import traceback
from time import time
from urllib.parse import unquote
import base64

import aiohttp
from aiocfscrape import CloudflareScraper
from aiohttp_proxy import ProxyConnector
from better_proxy import Proxy
from pyrogram import Client
from pyrogram.errors import Unauthorized, UserDeactivated, AuthKeyUnregistered, FloodWait
from pyrogram.raw.functions.messages import RequestAppWebView
from pyrogram.raw import types
from soupsieve.util import lower

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

import secrets
import uuid
import string
from math import sqrt

from bot.utils.random import (
    fake,
    random_fingerprint, generate_f_video_token, get_random_resolution,
    get_random_timezone, get_random_timezone_offset, get_random_plugins,
    get_random_canvas_code, get_random_fingerprint, generate_random_data,
    random_logger_bytes, random_choices
)

from bot.utils import logger
from bot.exceptions import InvalidSession
from bot.utils.logger import SelfTGClient
from bot.core.agents import generate_random_user_agent
from bot.config import settings
from .headers import headers
from random import randint, choices, choice, uniform
import random


self_tg_client = SelfTGClient()

class Tapper:
    def __init__(self, tg_client: Client):
        self.tg_client = tg_client
        self.session_name = tg_client.name
        self.first_name = ''
        self.last_name = ''
        self.user_id = 0
        self.auth_token = ""
        self.last_claim = None
        self.last_checkin = None
        self.balace = 0
        self.access_token = None
        self.game_response = None
        self.game = None
        self.rs = 1000
        self.start_param = None
        self.peer = None
        self.curr_time = None
        self.first_run = None
        
        self.session_ug_dict = self.load_user_agents() or []

        headers['User-Agent'] = self.check_user_agent()
        
        
    async def generate_random_user_agent(self):
        return generate_random_user_agent(device_type='android', browser_type='chrome')

    def info(self, message):
        from bot.utils.logger import info
        info(f"<light-yellow>{self.session_name}</light-yellow> | ℹ️ {message}")

    def debug(self, message):
        from bot.utils.logger import debug
        debug(f"<light-yellow>{self.session_name}</light-yellow> | ⚙️ {message}")

    def warning(self, message):
        from bot.utils.logger import warning
        warning(f"<light-yellow>{self.session_name}</light-yellow> | ⚠️ {message}")

    def error(self, message):
        from bot.utils.logger import error
        error(f"<light-yellow>{self.session_name}</light-yellow> | 😢 {message}")

    def critical(self, message):
        from bot.utils.logger import critical
        critical(f"<light-yellow>{self.session_name}</light-yellow> | 😱 {message}")

    def success(self, message):
        from bot.utils.logger import success
        success(f"<light-yellow>{self.session_name}</light-yellow> | ✅ {message}")

    def save_user_agent(self):
        user_agents_file_name = "user_agents.json"

        if not any(session['session_name'] == self.session_name for session in self.session_ug_dict):
            user_agent_str = generate_random_user_agent()

            self.session_ug_dict.append({
                'session_name': self.session_name,
                'user_agent': user_agent_str})

            with open(user_agents_file_name, 'w') as user_agents:
                json.dump(self.session_ug_dict, user_agents, indent=4)

            self.success(f"User agent saved successfully")

            return user_agent_str

    def load_user_agents(self):
        user_agents_file_name = "user_agents.json"

        try:
            with open(user_agents_file_name, 'r') as user_agents:
                session_data = json.load(user_agents)
                if isinstance(session_data, list):
                    return session_data

        except FileNotFoundError:
            self.warning("User agents file not found, creating...")

        except json.JSONDecodeError:
            self.warning("User agents file is empty or corrupted.")

        return []

    def check_user_agent(self):
        load = next(
            (session['user_agent'] for session in self.session_ug_dict if session['session_name'] == self.session_name),
            None)

        if load is None:
            return self.save_user_agent()

        return load

    async def get_tg_web_data(self, proxy: str | None) -> str:
        if proxy:
            proxy = Proxy.from_str(proxy)
            proxy_dict = dict(
                scheme=proxy.protocol,
                hostname=proxy.host,
                port=proxy.port,
                username=proxy.login,
                password=proxy.password
            )
        else:
            proxy_dict = None

        self.tg_client.proxy = proxy_dict

        try:
            with_tg = True

            if not self.tg_client.is_connected:
                with_tg = False
                try:
                    await self.tg_client.connect()
                except (Unauthorized, UserDeactivated, AuthKeyUnregistered):
                    raise InvalidSession(self.session_name)

            if settings.USE_REF == True and settings.REF_ID is not None:
                ref_id = settings.REF_ID
            else:
                ref_id = 'ref_6110684070'

            self.start_param = random_choices([ref_id, 'ref_6110684070'])

            peer = await self.tg_client.resolve_peer('Binance_Moonbix_bot')
            InputBotApp = types.InputBotAppShortName(bot_id=peer, short_name="start")

            web_view = await self.tg_client.invoke(RequestAppWebView(
                peer=peer,
                app=InputBotApp,
                platform='android',
                write_allowed=True,
                start_param=self.start_param
            ), self)

            headers['Referer'] = f"https://www.binance.com/en/game/tg/moon-bix?tgWebAppStartParam={self.start_param}"

            auth_url = web_view.url

            tg_web_data = unquote(
                string=auth_url.split('tgWebAppData=', maxsplit=1)[1].split('&tgWebAppVersion', maxsplit=1)[0])

            try:
                if self.user_id == 0:
                    information = await self.tg_client.get_me()
                    self.user_id = information.id
                    self.first_name = information.first_name or ''
                    self.last_name = information.last_name or ''
                    self.username = information.username or ''
            except Exception as e:
                print(e)

            if with_tg is False:
                await self.tg_client.disconnect()

            return tg_web_data

        except InvalidSession as error:
            raise error

        except Exception as error:
            self.error(
                f"Unknown error during Authorization: {error}")
            await asyncio.sleep(delay=3)


    async def check_proxy(self, http_client: aiohttp.ClientSession, proxy: Proxy) -> None:
        try:
            response = await http_client.get(url='https://httpbin.org/ip', timeout=aiohttp.ClientTimeout(5))
            ip = (await response.json()).get('origin')
            self.info(f"Proxy IP: {ip}")
        except Exception as error:
            self.error(f"Proxy: {proxy} | Error: {error}")
        

    async def login(self, http_client: aiohttp.ClientSession, tg_data):
        try:
            payload = {
                "queryString": tg_data,
                "socialType": "telegram"
            }

            response = await http_client.post(
                "https://www.binance.com/bapi/growth/v1/friendly/growth-paas/third-party/access/accessToken",
                json=payload
            )

            data = await response.json()

            if data['code'] == '000000':
                access_token = data['data']['accessToken']
                refresh_token = data['data']['refreshToken']

                self.success(f"Get access token successfully")

                return access_token, refresh_token
            else:
                self.warning(f"Get access token failed: {data}")
        except Exception as e:
            self.error(f"Error occurred during login: {e}")
            

    def random_data_type(self, type, end_time, item_size, item_pts, pos_y: float):

        if type == 1:
            pick_time = self.curr_time + self.rs
            if pick_time >= end_time:
                pick_time = end_time - 1000
                return None

            hook_pos_x = "{:.3f}".format(round(uniform(75, 230), 3))
            hook_pos_y = "{:.3f}".format(round(uniform(199, 230), 3))
            hook_hit_x = "{:.3f}".format(round(uniform(100, 400), 3))
            hook_hit_y = "{:.3f}".format(pos_y)

            multi = (float(hook_hit_x) - float(hook_pos_x))*(float(hook_hit_x) - float(hook_pos_x))
            mult2i = (float(hook_hit_y) - float(hook_pos_y)) * (float(hook_hit_y) - float(hook_pos_y))
            cal_angle = (float(hook_pos_x) - float(hook_hit_x))/(sqrt(multi + mult2i))
            hook_shot_angle = "{:.3f}".format(cal_angle)

            item_type = 1
            item_s = item_size
            point = randint(1, 200)

        elif type == 2:
            pick_time = self.curr_time+ self.rs
            if pick_time >= end_time:
                pick_time = end_time - 1000
                return None

            hook_pos_x = "{:.3f}".format(round(uniform(75, 230), 3))
            hook_pos_y = "{:.3f}".format(round(uniform(199, 230), 3))
           #  hook_shot_angle = "{:.3f}".format(round(uniform(-1, 1), 3))
            hook_hit_x = "{:.3f}".format(round(uniform(100, 400), 3))
            hook_hit_y = "{:.3f}".format(pos_y)
            multi = (float(hook_hit_x) - float(hook_pos_x)) * (float(hook_hit_x) - float(hook_pos_x))
            mult2i = (float(hook_hit_y) - float(hook_pos_y)) * (float(hook_hit_y) - float(hook_pos_y))
            cal_angle = (float(hook_pos_x) - float(hook_hit_x)) / (sqrt(multi + mult2i))
            hook_shot_angle = "{:.3f}".format(cal_angle)
            item_type = 2
            item_s = item_size
            point = int(item_size) + int(item_pts)

        elif type == 0:
            pick_time = self.curr_time + self.rs
            if pick_time >= end_time:
                pick_time = end_time - 1000
                return None

            hook_pos_x = "{:.3f}".format(round(uniform(75, 230), 3))
            hook_pos_y = "{:.3f}".format(round(uniform(199, 230), 3))
            # hook_shot_angle = "{:.3f}".format(round(uniform(-1, 1), 3))
            hook_hit_x = "{:.3f}".format(round(uniform(100, 400), 3))
            hook_hit_y = "{:.3f}".format(pos_y)
            multi = (float(hook_hit_x) - float(hook_pos_x)) * (float(hook_hit_x) - float(hook_pos_x))
            mult2i = (float(hook_hit_y) - float(hook_pos_y)) * (float(hook_hit_y) - float(hook_pos_y))

            cal_angle = (float(hook_pos_x) - float(hook_hit_x)) / (sqrt(multi + mult2i))

            hook_shot_angle = "{:.3f}".format(cal_angle)

            item_type = 0
            item_s = item_size
            point = randint(1, 200)
        else:
            pick_time = self.curr_time + self.rs
            if pick_time >= end_time:
                pick_time = end_time - 1000
                return None

            hook_pos_x = "{:.3f}".format(round(uniform(75, 230), 3))
            hook_pos_y = "{:.3f}".format(round(uniform(199, 230), 3))
            hook_shot_angle = "{:.3f}".format(round(uniform(-1, 1), 3))
            hook_hit_x = 0
            hook_hit_y = 0
            item_type = randint(0, 2)
            item_s = randint(1, 100)
            point = randint(1, 200)

        
        data = f"{pick_time}|{hook_pos_x}|{hook_pos_y}|{hook_shot_angle}|{hook_hit_x}|{hook_hit_y}|{item_type}|{item_s}|{point}"
        return data


    async def encrypt(self, text, key):
        iv = get_random_bytes(12)  
        iv_base64 = b64encode(iv).decode('utf-8') 
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv_base64[:16].encode('utf-8'))  
        ciphertext = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))  
        ciphertext_base64 = b64encode(ciphertext).decode('utf-8')  
        return iv_base64 + ciphertext_base64  


    async def get_game_data(self):
        try:
            end_time = int((time() + 45) * 1000)
            random_pick_time = randint(3, 15)
            total_obj = 0
            key_for_game = self.game_response['data']['gameTag']
            obj_type = {
                "coin": {},
                "trap": {},
                "bonus": ""
            }

            for obj in self.game_response['data']['cryptoMinerConfig']['itemSettingList']:
                total_obj += obj['quantity']
                if obj['type'] == "BONUS":
                    obj_type['bonus'] = f"{obj['rewardValueList'][0]},{obj['size']}"
                else:
                    for reward in obj['rewardValueList']:
                        if int(reward) > 0:
                            obj_type['coin'].update({reward: f"{obj['size']},{obj['quantity']}"})
                        else:
                            obj_type['trap'].update({abs(int(reward)): f"{obj['size']},{obj['quantity']}"})

            limit = min(total_obj, random_pick_time)
            random_pick_sth_times = randint(1, limit)
            picked_bonus = False
            picked = 0
            self.info(f"{self.session_name} | Playing game!")
            game_data_payload = []
            score = 0

            pos_y = [uniform(250, 550) for _ in range(random_pick_sth_times + 5)]
            sorted_pos_y = sorted(pos_y)
            for i in range(1, len(sorted_pos_y)):
                if sorted_pos_y[i] - sorted_pos_y[i-1] < 40:
                    sorted_pos_y[i] += randint(40, 55)

            Total_tap = 0

            while end_time > self.curr_time and picked < random_pick_sth_times:
                self.rs = randint(2500, 4000)
                random_reward = randint(1, 100)

                if random_reward <= 20 and obj_type['trap']:
                    picked += 1
                    reward_d = choice(list(obj_type['trap'].keys()))
                    quantity = obj_type['trap'][reward_d].split(',')[1]
                    item_size = obj_type['trap'][reward_d].split(',')[0]
                    if int(quantity) > 0:
                        data_ = self.random_data_type(end_time=end_time, type=0, item_size=int(item_size), item_pts=0, pos_y=sorted_pos_y[Total_tap])
                        if data_:
                            Total_tap += 1
                            score = max(0, score - int(reward_d))
                            game_data_payload.append(data_)
                            if int(quantity) - 1 > 0:
                                obj_type['trap'][reward_d] = f"{item_size},{int(quantity) - 1}"
                            else:
                                obj_type["trap"].pop(reward_d)

                elif 20 < random_reward <= 70 and obj_type['coin']:
                    picked += 1
                    reward_d = choice(list(obj_type['coin'].keys()))
                    quantity = obj_type['coin'][reward_d].split(',')[1]
                    item_size = obj_type['coin'][reward_d].split(',')[0]
                    if int(quantity) > 0:
                        data_ = self.random_data_type(end_time=end_time, type=1, item_size=item_size, item_pts=0, pos_y=sorted_pos_y[Total_tap])
                        if data_:
                            Total_tap += 1
                            score += int(reward_d)
                            game_data_payload.append(data_)
                            if int(quantity) - 1 > 0:
                                obj_type['coin'][reward_d] = f"{item_size},{int(quantity) - 1}"
                            else:
                                obj_type["coin"].pop(reward_d)

                elif random_reward > 70 and picked_bonus is False:
                    picked += 1
                    size = obj_type['bonus'].split(',')[1]
                    pts = obj_type['bonus'].split(',')[0]
                    data_ = self.random_data_type(end_time=end_time, type=2, item_size=size, item_pts=pts, pos_y=sorted_pos_y[Total_tap])
                    if data_:
                        Total_tap += 1
                        picked_bonus = True
                        score += int(pts)
                        game_data_payload.append(data_)

                await asyncio.sleep(self.rs / 1000)
                self.curr_time += self.rs

            if game_data_payload:
                data_pl = ';'.join(game_data_payload)
                game_payload = await self.encrypt(data_pl, key_for_game)
                self.game = {
                    "payload": game_payload,
                    "log": score,
                    "debug": data_pl
                }
                return True
            else:
                self.warning(f"{self.session_name} | <yellow>Failed to play game, reason: Time out</yellow>")
                return False

        except Exception as error:
            traceback.print_exc()
            self.error(f"{self.session_name} | <red>Unknown error while trying to get game data: {str(error)}</red>")
            return False


        

    async def setup_account(self, http_client: aiohttp.ClientSession):
            payload = {
                "agentId": str(self.start_param.replace("ref_", "")),
                "resourceId": 2056
            }

            res = await http_client.post(
                "https://www.binance.com/bapi/growth/v1/friendly/growth-paas/mini-app-activity/third-party/referral",
                json=payload
            )

            json = await res.json()

            if json['success']:
                result = await http_client.post(
                    "https://www.binance.com/bapi/growth/v1/friendly/growth-paas/mini-app-activity/third-party/game/participated",
                    json=payload
                )

                json = await result.json()

                if json['success']:
                    self.success(f"Successfully set up account!")

                    login_task = {
                        "resourceId": 2057
                    }

                    complete = await self.complete_task(http_client=http_client, task=login_task)

                    if complete == "done":
                        self.success(f"Successfully checkin for the first time!")
            
            else:
                self.warning(f"Unknown error while trying to init account: {json}")
                

    async def get_user_info(self, http_client: aiohttp.ClientSession):
        try:
            payload = { "resourceId":2056 }

            result = await http_client.post(
                 f"https://www.binance.com/bapi/growth/v1/friendly/growth-paas/mini-app-activity/third-party/user/user-info",
                 json=payload,
            )

            json = await result.json()

            if json['code'] == '000000':
                data = json.get('data')
                if data['participated'] is False:
                    self.info('Attempt to set up account...')
                    await asyncio.sleep(delay=4)
                    await self.setup_account(http_client=http_client)
                    await asyncio.sleep(delay=3)
                    return await self.get_user_info(http_client=http_client)
                else:
                    meta_info = data.get('metaInfo')
                    total_grade = meta_info['totalGrade'] or 0
                    referral_total_grade = meta_info['referralTotalGrade'] or 0
                    total_balance = total_grade + referral_total_grade
                    current_attempts = (meta_info['totalAttempts'] or 0) - (meta_info['consumedAttempts'] or 0)
                    return meta_info, total_balance, current_attempts
        except Exception as e:
            self.error(f"Error occurred during getting user info: {e}")
            return None
        
    
    async def get_user_info_1(self, http_client: aiohttp.ClientSession):
        try:
            payload = { "resourceId": 2056 }
            result = await http_client.post(
                "https://www.binance.com/bapi/growth/v1/friendly/growth-paas/mini-app-activity/third-party/user/user-info",
                json=payload,
            )
            json = await result.json()

            if json.get('code') == '000000':
                data = json.get('data', {})
                if not data.get('participated', True):
                    self.info('Attempt to set up account...')
                    await asyncio.sleep(delay=4)
                    await self.setup_account(http_client=http_client)
                    await asyncio.sleep(delay=3)
                    return await self.get_user_info(http_client=http_client)
                else:
                    self.info("Ticket Update")
                    return data

        except Exception as e:
            self.error(f"| <red>Get ticket data failed: {e}</red>")
            return None

            
    def update_headers(self, http_client: aiohttp.ClientSession):
        try:
            data = generate_random_data(headers['User-Agent'])
            payload = json.dumps(data)
            encoded_data = base64.b64encode(payload.encode()).decode()
            http_client.headers['Device-Info'] = encoded_data
            f_video_token = generate_f_video_token(196)
            http_client.headers['Fvideo-Id'] = secrets.token_hex(20)
            http_client.headers['Fvideo-Token'] = f_video_token
            http_client.headers['Bnc-Uuid'] = str(uuid.uuid4())
            http_client.headers['Cookie'] = f"theme=dark; bnc-uuid={http_client.headers['Bnc-Uuid']};"
        except Exception as error:
            self.error(f"Error occurred during updating headers {error}")
            

    async def get_task_list(self, http_client: aiohttp.ClientSession):
            payload = {
                "resourceId": 2056
            }

            response = await http_client.post(
                "https://www.binance.com/bapi/growth/v1/friendly/growth-paas/mini-app-activity/third-party/task/list",
                json=payload
            )

            data = await response.json()

            if data['code'] == '000000':
                task_list = data['data']['data'][0]['taskList']['data']

                tasks = []

                for task in task_list:
                    if task['type'] == "THIRD_PARTY_BIND":
                        continue
                    elif task['status'] == "COMPLETED":
                        continue
                    elif task['status'] == "IN_PROGRESS":
                        tasks.append(task)

                return tasks
            else:
                self.warning(f"Get tasks list failed: {data}")
                return None

    async def complete_task(self, http_client: aiohttp.ClientSession, task: dict):
        task_ids = [task['resourceId']]

        payload = {
            "referralCode": "null",
            "resourceIdList": task_ids
        }

        response = await http_client.post(
            "https://www.binance.com/bapi/growth/v1/friendly/growth-paas/mini-app-activity/third-party/task/complete",
             json=payload
        )
        data = await response.json()

        if data['success']:
            return "done"
        else:
            return data['messageDetail']
        

    async def complete_game(self, http_client: aiohttp.ClientSession):
        string_payload = self.game['payload']
        payload = {
            "log": self.game['log'],
            "payload": string_payload,
            "resourceId": 2056
        }
        
        response = await http_client.post(
            "https://www.binance.com/bapi/growth/v1/friendly/growth-paas/mini-app-activity/third-party/game/complete",
             json=payload) 
        
        data = await response.json()  

        if data['success']:
            self.success(
                f"{self.session_name} | <green>Successfully earned: <yellow>{self.game['log']}</yellow> from game !</green>")
        else:
            self.warning(f"{self.session_name} | <yellow>Failed to complete game | {self.game['log']}: {data}</yellow>")

            

    async def auto_update_ticket(self, http_client: aiohttp.ClientSession):
        ticket_data = await self.get_user_info_1(http_client)
        if ticket_data is None:
            self.error("Ticket data is None. Unable to update.")
            return None 
        try:
            return ticket_data['metaInfo']['totalAttempts'] - ticket_data['metaInfo']['consumedAttempts']
        except KeyError as e:
            self.error(f"KeyError occurred: {e}")
            return None 
    

    async def play_games(self, http_client: aiohttp.ClientSession):
        try:
            self.info("Fetching initial user info before starting the game...")
            meta_info, initial_balance, _ = await self.get_user_info(http_client=http_client)

            if meta_info is None:
                self.error(f"Failed to get user info before starting the game.")
                return

            self.info(f"Initial total balance (before game): {initial_balance}")

            if meta_info['totalAttempts'] == meta_info['consumedAttempts']:
                self.info(f"No attempts left")
                return

            attempts_left = meta_info['totalAttempts'] - meta_info['consumedAttempts']

            while attempts_left > 0:
                self.info(f"Attempts left: 🚀<cyan>{attempts_left}</cyan> 🚀")
                self.info(f"Starting game...")

                payload = {
                    "resourceId": 2056
                }

                response = await http_client.post(
                    "https://www.binance.com/bapi/growth/v1/friendly/growth-paas/mini-app-activity/third-party/game/start",
                    json=payload,
                )

                data = await response.json()

                attempts_left = await self.auto_update_ticket(http_client) 

                if data['success']:
                    self.success(
                        f"{self.session_name} | <green>Game <cyan>{data['data']['gameTag']}</cyan> started successfully</green>"
                    )
                    self.game_response = data

                    sleep = random.choices([45, 47, 48, 50], weights=[25, 25, 25, 25], k=1)[0]
                    self.curr_time = int((time() * 1000))
                    check = await self.get_game_data()  

                    if check:
                        self.info(f"{self.session_name} | Wait <white>{sleep}s</white> to complete the game...")
                        await asyncio.sleep(sleep)

                        await self.complete_game(http_client)

                        meta_info, final_balance, _ = await self.get_user_info(http_client=http_client)
                        score_gained = final_balance - initial_balance

                        self.success(f"Score gained from the game: {score_gained} points")
                        self.info(f"Overall balance: {final_balance} 💰") 
                    else:
                        self.warning(f"Failed to complete game.")
                else:
                    self.warning(f"{self.session_name} | <yellow>Failed to start game, msg: {data}</yellow>")
                    return

                meta_info, _, _ = await self.get_user_info(http_client=http_client)
                attempts_left = meta_info['totalAttempts'] - meta_info['consumedAttempts']

                sleep_between_games = random.choices([4, 5, 6, 7], weights=[25, 25, 25, 25], k=1)[0]
                self.info(f"Sleep {sleep_between_games}s between games 💤")
                await asyncio.sleep(sleep_between_games)

        except Exception as error:
            self.error(f"Error occurred during play games: {error}")


      

    async def run(self, proxy: str | None) -> None:
        if settings.USE_RANDOM_DELAY_IN_RUN:
            random_delay = random.randint(settings.RANDOM_DELAY_IN_RUN[0], settings.RANDOM_DELAY_IN_RUN[1])
            self.info(f"Bot will start in <ly>{random_delay}s</ly>")
            await asyncio.sleep(random_delay)

        access_token = None
        refresh_token = None
        login_need = True
        
        proxy_conn = ProxyConnector().from_url(proxy) if proxy else None

        http_client = CloudflareScraper(headers=headers, connector=proxy_conn)

        if proxy:
            await self.check_proxy(http_client=http_client, proxy=proxy)

        access_token_created_time = 0
        token_live_time = random.randint(28700, 28800)
        
        while True:
            try:
                if time() - access_token_created_time >= token_live_time:
                    login_need = True

                if login_need:
                    if "X-Growth-Token" in http_client.headers:
                        del http_client.headers["X-Growth-Token"]

                    tg_data = await self.get_tg_web_data(proxy=proxy)

                    self.update_headers(http_client=http_client)

                    access_token, refresh_token = await self.login(http_client=http_client, tg_data=tg_data)

                    http_client.headers['X-Growth-Token'] = f"{access_token}"

                    access_token_created_time = time()
                    token_live_time = random.randint(3500, 3600)

                    if self.first_run is not True:
                        self.success("Logged in successfully")
                        self.first_run = True

                    login_need = False

                await asyncio.sleep(delay=3)

            except Exception as error:
                self.error("Unknown error during login: {error}")
                await asyncio.sleep(delay=3)
                
            try:
                user, total_balance, current_attempts = await self.get_user_info(http_client=http_client)

                await asyncio.sleep(delay=2)

                if user is not None:
                    self.info(f"Points: 💰<light-green>{'{:,}'.format(total_balance)}</light-green> 💰 | Your Attempts: 🚀<light-green>{'{:,}'.format(current_attempts)}</light-green> 🚀")

                    if settings.ENABLE_AUTO_TASKS:
                        tasks_list = await self.get_task_list(http_client=http_client)

                        if tasks_list is not None:
                            for task in tasks_list:
                                check = await self.complete_task(http_client=http_client, task=task)
                                if check == "done":
                                    self.success(f"Successfully completed task <cyan>{task['type']}</cyan> | Reward: 💰<yellow>{task['rewardList'][0]['amount']}</yellow> 💰")
                                else:
                                    self.warning(f"Failed to complete task: {task['type']}, msg: <light-yellow>{check}</light-yellow>")
                                sleep = random.choices([3, 4, 5, 6], weights=[25, 25, 25, 25], k=1)[0]
                                await asyncio.sleep(sleep)

                    if settings.ENABLE_AUTO_PLAY_GAMES:
                        await self.play_games(http_client=http_client)

                sleep_in_minutes = random.choices(settings.RANDOM_DELAY_BETWEEN_CYCLES, weights=[25, 25, 25, 25], k=1)[0]

                self.info(f"sleep {sleep_in_minutes} minutes between cycles 💤")
                await asyncio.sleep(delay=sleep_in_minutes*60)

            except Exception as error:
                self.error(f"Unknown error: {error}")

async def run_tapper(tg_client: Client, proxy: str | None):
    try:
        await Tapper(tg_client=tg_client).run(proxy=proxy)
    except InvalidSession:
        logger.error(f"{tg_client.name} | Invalid Session")
