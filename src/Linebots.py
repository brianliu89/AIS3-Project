from flask import Flask
app = Flask(__name__)

from flask import Flask, request, abort
from linebot import LineBotApi, WebhookHandler
from linebot.exceptions import InvalidSignatureError
from linebot.models import (
    MessageEvent,TextMessage,TextSendMessage, ImageSendMessage,
    StickerSendMessage, LocationSendMessage, QuickReply,
    QuickReplyButton, MessageAction
)
from urllib.parse import urlparse
from secret import CHANNEL_ACCESS_TOKEN, CHANNEL_SECRET
from url_judge import url_judge, LABEL # check if input is url or ip
import datetime
from API_Converge import grab_url, get_address_from_coordinates, get_dates_info
logpath = 'log.txt'

line_bot_api = LineBotApi(CHANNEL_ACCESS_TOKEN)
handler = WebhookHandler(CHANNEL_SECRET)

@app.route("/callback", methods=['POST'])
def callback():
    """ Webhook handle """
    # get X-Line-Signature header value
    signature = request.headers['X-Line-Signature']
    # get request body as text
    body = request.get_data(as_text=True)
    # handle webhook body
    try:
        handler.handle(body, signature)
    except InvalidSignatureError:
        abort(400)
    return 'OK'

@handler.add(MessageEvent, message=TextMessage)
def handle_message(event):
    """
        When user input text message, this function will be called
        to process url or ip and return a accessment report
    """
    url_to_scan = event.message.text # input message
    # --- 寫log
    file = open(logpath,'a')
    print(datetime.datetime.now,file=file,end=' - ')
    print(url_to_scan,file = file,end='requests = ')
    # ---
    label = url_judge(url_to_scan) # check if input is url or ip
    if label == LABEL[2] or url_to_scan == "0.0.0.0": # input is invalid
        # Send error message to user
        print('error',file = file)
        file.close()
        line_bot_api.reply_message(event.reply_token, TextSendMessage(text="請輸入 URL 或是 IP!"))
    else:
        """ Call api here """
        """ Report """
        report,Country,la,lo = grab_url(url_to_scan,label)
        # line_bot_api.reply_message(event.reply_token, TextSendMessage(text="回傳的報告"))
        """ Map """
        print('success',file = file)
        file.close()
        address = get_address_from_coordinates(la, lo)

        """ Reply """
        line_bot_api.reply_message(event.reply_token, 
            [
                TextSendMessage(
                    text=report 
                ), 
                LocationSendMessage(
                    title = Country,
                    address = address,
                    latitude = la, # 緯度
                    longitude = lo # 經度
                )
            ]
        )
if __name__ == '__main__':
    app.run(port=5000, debug=True)
