#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os	#ファイルシステム操作
import socket	#タイムアウトの時間を設定(標準が長すぎる)
import logging	#ログの出力・制御
import pytz     #タイムゾーン   追加インストール
import base64
from StringIO import StringIO	#文字列objectをファイルobjectのように扱う(getvalueメソッド)
from xml.etree import ElementTree	#xmlファイル読み込みhttps://docs.python.jp/3/library/xml.etree.elementtree.html
from BaseHTTPServer import HTTPServer	
from SocketServer import ThreadingMixIn
from SimpleHTTPServer import SimpleHTTPRequestHandler
from datetime import datetime, timedelta    #時間取得

class NonBlockingHTTPServer(ThreadingMixIn, HTTPServer):
    pass


class WebLogicHandler(SimpleHTTPRequestHandler):
    logger = None       #loggerを初期化

    protocol_version = "HTTP/1.1"
    body_data = ""
    EXPLOIT_STRING = "</void>"
    ###XML SOAP1.1 ファルトによる記述
    PATCHED_RESPONSE = """<?xml version='1.0' encoding='UTF-8'?><S:Envelope xmlns:S="http://schemas.xmlsoap.org/soa""" \
                       """p/envelope/"><S:Body><S:Fault xmlns:ns4="http://www.w3.org/2003/05/soap-envelope"><faultc""" \
                       """ode>S:Server</faultcode><faultstring>Invalid attribute for element void:class</faultstrin""" \
                       """g></S:Fault></S:Body></S:Envelope>"""
    GENERIC_RESPONSE = """<?xml version='1.0' encoding='UTF-8'?><S:Envelope xmlns:S="http://schemas.xmlsoap.org/soa""" \
                       """p/envelope/"><S:Body><S:Fault xmlns:ns4="http://www.w3.org/2003/05/soap-envelope"><faultc""" \
                       """ode>S:Server</faultcode><faultstring> The current event is not START_ELEMENT but 2</faults""" \
                       """tring></S:Fault></S:Body></S:Envelope>"""
    OPTIONS_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?><result><state>ok</state><desc>Save successfully</desc></result>"""


#このスクリプトのあるディレクトリを絶対パスで取得　/usr/scr/app
    basepath = os.path.dirname(os.path.abspath(__file__))

    alert_function = None   #alert関数を格納

    #self == インスタンスrequestHandlerを意味
    def setup(self):
        SimpleHTTPRequestHandler.setup(self)   #恐らくリクエストヘッダーオブジェクトsocketメソッド
        self.request.settimeout(1)  #謎

#weblogicのversionを返す　呼び出す場所謎
    def version_string(self):
        return 'WebLogic Server 10.3.6.0.171017 PSU Patch for BUG26519424 TUE SEP 12 18:34:42 IST 2017 WebLogic ' \
               'Server 10.3.6.0 Tue Nov 15 08:52:36 PST 2011 1441050 Oracle WebLogic Server Module Dependencies ' \
               '10.3 Thu Sep 29 17:47:37 EDT 2011 Oracle WebLogic Server on JRockit Virtual Edition Module ' \
               'Dependencies 10.3 Wed Jun 15 17:54:24 EDT 2011'

    def send_head(self):    #do_Post ,do_sendfileメソッド
        # send_head will return a file object that do_HEAD/GET will use     do_HEAD/GETメソッドが使うファイルオブジェクトを返す
        # do_GET/HEAD are already implemented by SimpleHTTPRequestHandler   do_HEAD/GETメソッドは既にSimpleHTTPRequestHandlerで実装されている。
        
        #basename パスの末尾を表示  rstrip 末尾の/を全て取り除く
        filename = os.path.basename(self.path.rstrip('/'))  #リクエストパス
        
        if self.path == '/':
            return self.send_file('post.html')
        elif filename == 'wls-wsat' :  # don't allow dir listing
            return self.send_file('403.html', 403)
        elif 'general' in self.path:
            return self.send_file(str(filename)+'.xml')
        else:
            return self.send_file(filename)

    def do_POST(self):
        data_len = int(self.headers.get('Content-length', 0))   #BaseHTTPServerのheadのkey(Content-length)のvalueをintでとる。noneなら0にする
        data = self.rfile.read(data_len) if data_len else ''    #BaseHTTPServerのrfileをdata_lenByte分読み込む
        self.body_data = data.decode()
        resp = 500
        
        if self.EXPLOIT_STRING in data:                         #"</void>"の有無確認 EXPLOIT_STRING==</void>
            xml = ElementTree.fromstring(data)                  #リクエストボディのxmlの解析
            payload = []
            for void in xml.iter('void'):                       #voidタグをイテレート
                for s in void.iter('string'):                   #voidタグ内のstringタグをイテレート
                    payload.append(s.text)                      #イテレートタグに入ってるbin/bashコマンドを配列payloadに格納

            self.alert_function(self, payload)                  #alert関数にselfとpyload関数を渡す
            body = self.PATCHED_RESPONSE
        elif 'options' in self.path:
            body = self.OPTIONS_RESPONSE   
            resp = 200
        else:
            body = self.GENERIC_RESPONSE


        self.send_response(resp)                               #サーバーエラー
        self.send_header('Content-Length', int(len(body)))              #ヘッダにContent-LengthとContent-Typeを追加
        if body == self.OPTIONS_RESPONSE:
            self.send_header('Content-Type','application/xml')
        else:
            self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(body)  #リクエストボディにbody書き込み

    def send_file(self, filename, status_code=200):
        try:                                #例外処理条件
            with open(os.path.join(self.basepath, 'wls-wsat', filename), 'rb') as fh:   #/usr/scr/app/wls-wsat/の中をバイナリモードでopen。fhとして
                body = fh.read()     
                if body.find('%%HOST%%'):       
                    body = body.replace('%%HOST%%', str(self.headers.get('Host')))                                           
                self.send_response(status_code)
                self.send_header('Content-Length', int(len(body)))
                if filename == 'general.xml':
                    self.send_header('Content-Type', 'application/xml')
                else:    
                    self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.end_headers()
                return StringIO(body)                       #結局色々したファイルの中を返す
        except IOError:                     #例外時処理
            return self.send_file('post.html')          #/wls-wsatに無ければ404を出す

    def log_message(self, format, *args):
        self.logger.debug("%s - - [%s] %s" %
                          (self.client_address[0],
                           self.log_date_time_string(),
                           format % args))

    def handle_one_request(self):
        """Handle a single HTTP request.
        Overriden to not send 501 errors
        """
        clientip = self.client_address[0]           #接続先IPaddress
        separator = " "
        #self.requestline                           リクエストライン　GET~HTTP1.1


        self.close_connection = True                            #変数定義
        try:
            self.raw_requestline = self.rfile.readline(65537)   #raw_reqにbody部分を取り込む(65537byte分)　65537ナゾのsize指定
            if len(self.raw_requestline) > 65536:               #raw_reqの文字数が65536以上であれば
                self.requestline = ''
                self.request_version = ''
                self.command = ''
                self.close_connection = 1                       #上3つの変数に空白を代入し、close_coneに1を代入
                return
            if not self.raw_requestline:                        #raw_requestlineが0のとき
                self.close_connection = 1
                return
            if not self.parse_request():                        #parse_request謎　関数
                # An error code has been sent, just exit
                return
            mname = 'do_' + self.command
            if not hasattr(self, mname):
                self.log_request()
                self.close_connection = True
                return
            method = getattr(self, mname)
            method()
            self.wfile.flush()  # actually send the response if not already done.

            #logging
            hostname = None
            if "host" in self.headers:
    
                if self.headers["host"].find(" ") == -1:
                    hostname = self.headers["host"]
                else:
                    hostname = self.headers["host"].split(" ")[0]
                if hostname.find(":") == -1:
                    hostname = hostname + ":80"
            else:
                hostname = "blank:80"

            body = self.body_data
            request_all = self.requestline + "\n" + str(self.headers) + body
            logging_access("[{time}]{s}{clientip}{s}{hostname}{s}\"{requestline}\"{s}{requestall}\n".format(
                                                                    time=get_time(),
                                                                    clientip=clientip,
                                                                    hostname=hostname,
                                                                    requestline=self.requestline,
                                                                    requestall=base64.b64encode(request_all.encode('utf-8')).decode('utf-8'),
                                                                    s=separator
                                                                    ))
        except socket.timeout, e:
            # a read or a write timed out.  Discard this connection
            self.log_error("Request timed out: %r", e)
            self.close_connection = 1
            return

    #継ぎ足しlogging
def logging_access(log):
    pathlog = '/etc/weblogic2/weblogic_honeypot/access_log'
    with open(pathlog, 'a') as f:
        f.write(log)

def keystoreplus(lists):
    stl = ""
    for i in lists:
        st = "<keyStoreItem><id>1548233930480</id><keyStore>{name}</keyStore></keyStoreItem>".format(name=i)
        stl += st 
    KEYSTORE_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?><setting id="security"><section name="key_store_list">"""\
                        """<options xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="securityOptions">"""\
                        """{all}</options></section></setting>""".format(all=stl)
    return KEYSTORE_RESPONSE

def get_time():
    return "{0:%Y-%m-%d %H:%M:%S%z}".format(datetime.now(pytz.timezone('Asia/Tokyo')))

if __name__ == '__main__':  #weblogic.pyを参照時に実行されない様にする
    import click        #コマンドラインパーサー

    logging.basicConfig(level=logging.INFO)     #出力レベルがINFO(下から2番目)以上の物を出力
    logger = logging.getLogger()                #ルートロガーを生成

    @click.command()
    @click.option('-h', '--host', default='0.0.0.0', help='Host to listen')                     #host(h)オプション追加。デフォルトは0.0.0.0 helpは説明文
    @click.option('-p', '--port', default=8000, help='Port to listen', type=click.INT)          #port(p)オプション追加。デフォルトは8000 型をint型で定義
    @click.option('-v', '--verbose', default=False, help='Verbose logging', is_flag=True)       #verbose(v)オプション追加。デフォルトはFalse 
    def start(host, port, verbose): #optionで得られたもの　0.0.0.0, 8000, False
        """
           A low interaction honeypot for the Oracle Weblogic wls-wsat component capable of detecting CVE-2017-10271,
           a remote code execution vulnerability
        """
        def alert(cls, request, payload):
            logger.critical({               #criticalレベルでログ出力
                'src': request.client_address[0],
                'spt': request.client_address[1],
                'destinationServiceName': ' '.join(payload),
            })

        if verbose:
            logger.setLevel(logging.DEBUG)

        requestHandler = WebLogicHandler
        requestHandler.alert_function = alert
        requestHandler.logger = logger

        httpd = HTTPServer((host, port), requestHandler)    
        logger.info('Starting server on port {:d}, use <Ctrl-C> to stop'.format(port))
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        logger.info('Stopping server.')
        httpd.server_close()

    start()
