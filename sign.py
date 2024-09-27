# -*- coding: utf8 -*-
import json
import qrcode
import requests
import datetime
import base64
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pksc1_v1_5
from Crypto.PublicKey import RSA


def encrypt(password, public_key):
    rsakey = RSA.importKey(public_key)
    cipher = Cipher_pksc1_v1_5.new(rsakey)
    cipher_text = base64.b64encode(cipher.encrypt(password.encode()))
    return cipher_text.decode()


class GZHU(object):
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.client = requests.session()
        self.client.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:94.0) Gecko/20100101 Firefox/94.0',
        })
        self.url = {
            'scancode': 'http://libbooking.gzhu.edu.cn/scancode.html#/login?sta=1&sysid=1EW&lab=69&type=1',
            'user_info': 'http://libbooking.gzhu.edu.cn/ic-web/auth/userInfo',
            '101': 'http://libbooking.gzhu.edu.cn/ic-web/reserve?roomIds=100647013&resvDates=20220416&sysKind=8',
            '103': 'http://libbooking.gzhu.edu.cn/ic-web/reserve?roomIds=100647014&resvDates=20220416&sysKind=8',
            '202': 'http://libbooking.gzhu.edu.cn/ic-web/reserve?roomIds=100586595&resvDates=20220416&sysKind=8',
            '203': 'http://libbooking.gzhu.edu.cn/ic-web/reserve?roomIds=100586609&resvDates=20220416&sysKind=8',
            '204': 'http://libbooking.gzhu.edu.cn/ic-web/reserve?roomIds=100586613&resvDates=20220416&sysKind=8',
            '205': 'http://libbooking.gzhu.edu.cn/ic-web/reserve?roomIds=100586623&resvDates=20220416&sysKind=8',
            '206': 'http://libbooking.gzhu.edu.cn/ic-web/reserve?roomIds=100586625&resvDates=20220416&sysKind=8',
            '2C': 'http://libbooking.gzhu.edu.cn/ic-web/reserve?roomIds=100647017&resvDates=20220416&sysKind=8',
            '301': 'http://libbooking.gzhu.edu.cn/ic-web/reserve?roomIds=100586629&resvDates=20220416&sysKind=8',
            '303': 'http://libbooking.gzhu.edu.cn/ic-web/reserve?roomIds=100586631&resvDates=20220416&sysKind=8',
            '306': 'http://libbooking.gzhu.edu.cn/ic-web/reserve?roomIds=100586633&resvDates=20220416&sysKind=8',
            '307': 'http://libbooking.gzhu.edu.cn/ic-web/reserve?roomIds=100586633&resvDates=20220416&sysKind=8',
            '3A': 'http://libbooking.gzhu.edu.cn/ic-web/reserve?roomIds=100586637&resvDates=20220416&sysKind=8',
            '3C': 'http://libbooking.gzhu.edu.cn/ic-web/reserve?roomIds=100586639&resvDates=20220416&sysKind=8',
            '402': 'http://libbooking.gzhu.edu.cn/ic-web/reserve?roomIds=100586644&resvDates=20220416&sysKind=8',
            '406': 'http://libbooking.gzhu.edu.cn/ic-web/reserve?roomIds=100586647&resvDates=20220416&sysKind=8',
            '417': 'http://libbooking.gzhu.edu.cn/ic-web/reserve?roomIds=100586651&resvDates=20220416&sysKind=8',
            '4A': 'http://libbooking.gzhu.edu.cn/ic-web/reserve?roomIds=100586656&resvDates=20220416&sysKind=8',
            '4C': 'http://libbooking.gzhu.edu.cn/ic-web/reserve?roomIds=100586658&resvDates=20220416&sysKind=8',
            '501': 'http://libbooking.gzhu.edu.cn/ic-web/reserve?roomIds=100586660&resvDates=20220416&sysKind=8',
            '502': 'http://libbooking.gzhu.edu.cn/ic-web/reserve?roomIds=100586662&resvDates=20220416&sysKind=8',
            '511': 'http://libbooking.gzhu.edu.cn/ic-web/reserve?roomIds=100586665&resvDates=20220416&sysKind=8',
            '513': 'http://libbooking.gzhu.edu.cn/ic-web/reserve?roomIds=100586669&resvDates=20220416&sysKind=8',
            '514': 'http://libbooking.gzhu.edu.cn/ic-web/reserve?roomIds=100589684&resvDates=20220416&sysKind=8',
            '5C': 'http://libbooking.gzhu.edu.cn/ic-web/reserve?roomIds=100646980&resvDates=20220416&sysKind=8',
        }

    def loginLib(self, select_room):
        """
                :param select_room: '101’ or '103'
                :return:
                """
        self.client.headers.update({
            'Referer': 'http://libbooking.gzhu.edu.cn/',
            'Host': 'libbooking.gzhuedu.cn'
        })

        # 获得publicKey
        r1 = self.client.get('http://libbooking.gzhu.edu.cn/ic-web/login/publicKey')
        key = json.loads(r1.text)['data']
        publicKey = key['publicKey']
        nonceStr = key['nonceStr']
        psd = '{};{}'.format(self.password, nonceStr)
        print(r1)

        public_key = '-----BEGIN PUBLIC KEY-----\n' + publicKey + '\n-----END PUBLIC KEY-----'
        password = encrypt(psd, public_key)
        print('password:', password)

        login_data = {
            "bind": 0,
            "logonName": self.username,
            "password": password,
            "type": "",
            "unionId": ""
        }
        try:
            self.client.post('http://libbooking.gzhu.edu.cn/ic-web/phoneSeatReserve/login', json=login_data)
            r3 = self.client.get(self.url['user_info'])
            data = json.loads(r3.text)
            if data['message'] == '查询成功':
                self.client.headers.update({
                    'token': data['data']['token']
                })
                print('自习室系统登录成功')
                r4 = self.client.get(self.url[select_room])
                room_data = json.loads(r4.text)
                return room_data, data['data']['accNo']
        except Exception as e:
            title='登录失败'
            content=str(e)
            # 推送签到结果
            data = {"token": 'ed13cff5a1d746abb26cd06434415722', "title": title, "content": content}
            url = "http://www.pushplus.plus/send/"
            requests.post(url, json=data)
            raise 
        

    def sign(self, acc_no, dev_Sn):
        try:
            url0 = 'http://update.unifound.net/wxnotice/s.aspx?c=' + str(acc_no) + '_Seat_' + str(dev_Sn) + '_1EW'
            print("手动签到链接：", url0)

            # 获取预约号
            url = 'http://libbooking.gzhu.edu.cn/ic-web/phoneSeatReserve/login'
            data = {
                "bind": 0,
                "devSn": dev_Sn,
                "loginType": 2,
                "type": "1",
            }
            res = self.client.post(url, json=data)
            data = json.loads(res.text)
            print(data)
            resvId = data['data']['reserveInfo']['resvId']

            # 签到
            url2 = 'https://libbooking.gzhu.edu.cn/ic-web/phoneSeatReserve/sign'
            data2 = {
                "resvId": resvId,
            }
            
            feadback=self.client.post(url2, json=data2)
            text = json.loads(feadback.text)
            
            if feadback.status_code == 201:
                title='签到成功'
                content=text['message']
            else:
                # 生成二维码对象
                qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_H, box_size=10, border=4)
                qr.add_data(url)
                qr.make(fit=True)

                # 创建二维码图片
                image = qr.make_image(fill_color="black", back_color="white")
                
                # 保存图片
                save_url="sign.png"
                image.save(save_url) 
                
                title='签到失败'
                content='请通过手动链接：'+url0+'\n'+text['message']'
            
            # 推送签到结果
            data = {"token": 'ed13cff5a1d746abb26cd06434415722', "title": title, "content": content}
            url = "http://www.pushplus.plus/send/"
            requests.post(url, json=data)
            
        except Exception as e:
            title='程序异常'
            content=str(e)
            # 推送签到结果
            data = {"token": 'ed13cff5a1d746abb26cd06434415722', "title": title, "content": content}
            url = "http://www.pushplus.plus/send/"




def start():
    with open('config.json', 'r') as fp:
        cfg = json.load(fp)
        g = GZHU(cfg['username'], cfg['password'])
        room_datas, accNo = g.loginLib(cfg['room'])
        dev_id = ''
        for data in room_datas['data']:
            if data["devName"] == cfg['seat_id']:
                dev_Sn = data["devSn"]
                break
        g.sign(accNo, dev_Sn)


if __name__ == '__main__':
    start()
