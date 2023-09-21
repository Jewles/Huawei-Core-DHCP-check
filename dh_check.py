import time
import paramiko
import configparser
import re
import requests
import logging


class DHCPMonitor:
    def __init__(self, config_file="config.ini"):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        self.WEBHOOK_URL = self.config.get("WEBHOOK", "webhook_url")
        self.logger = self._setup_logger()

    def _setup_logger(self):
        logger = logging.getLogger("DHCPMonitor")
        logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

        file_handler = logging.FileHandler("dhcp_monitor.log")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)

        return logger

    def parse_vlan_range(self, vlan_range):
        start, end = map(int, vlan_range.split('-'))
        return list(range(start, end+1))

    def get_vlan_ids(self):
        vlan_range = self.config.get("VLAN", "vlan_id")
        return self.parse_vlan_range(vlan_range)

    def dingtalk_alert(self, vlan_id, used_value):
        message = f"VLAN {vlan_id} 已使用地址数量: {used_value}，10分钟后开始自动清理地址池"
        data = {
            "msgtype": "text",
            "text": {
                "content": message
            }
        }
        headers = {
            "Content-Type": "application/json"
        }
        response = requests.post(self.WEBHOOK_URL, json=data, headers=headers)
        if response.status_code == 200:
            self.logger.info(f"钉钉消息发送成功: {message}")
            time.sleep(600)
        else:
            self.logger.error("钉钉消息发送失败: {message}")

    def command_run(self, ssh_client, vlan_ids):
        ssh_shell = ssh_client.invoke_shell()
        ssh_shell.send("screen-length 0 temporary\n")  # Set terminal length to avoid paging

        for vlan_id in vlan_ids:
            command = "dis ip pool name vlan{} \n".format(vlan_id)
            ssh_shell.send(command)
            time.sleep(1)
            output = ssh_shell.recv(65535).decode('utf-8')

            used_match = re.search(r"Used\s+:\s*(\d+)", output)
            if used_match:
                used_value = int(used_match.group(1))
            else:
                used_value = 0

            print(f"VLAN {vlan_id} 已使用地址数量: {used_value}")

            if used_value > 500:
                self.dingtalk_alert(vlan_id, used_value)
                release_command = "reset ip pool name vlan{} all\n".format(vlan_id)
                ssh_shell.send(release_command)
                time.sleep(2)

                ssh_shell.send("y\n")
                time.sleep(1)

        ssh_shell.close()


    def ssh_login(self, hostname, username, pwd, port=22):
        try:
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh_client.connect(hostname=hostname, username=username, password=pwd, port=port)

            vlan_ids = self.get_vlan_ids()
            self.command_run(ssh_client, vlan_ids)

            ssh_client.close()

        except paramiko.AuthenticationException:
            self.logger.error("登陆失败！账号密码错误")
        except paramiko.SSHException as e:
            self.logger.error("SSH连接失败:", str(e))
        except Exception as e:
            self.logger.exception("发生异常:", str(e))

if __name__ == "__main__":
    dhcp_monitor = DHCPMonitor()
    hostname = dhcp_monitor.config.get('SSH', 'hostname')
    username = dhcp_monitor.config.get('SSH', 'username')
    pwd = dhcp_monitor.config.get('SSH', 'password')
    dhcp_monitor.ssh_login(hostname, username, pwd)