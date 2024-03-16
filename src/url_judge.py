"""
Written by XD3an.
"""
import re

LABEL = ["Domain", "IP", "Invalid"]
def url_judge(user_input):
    """ judge domain or ip using re """
    if re.match(r'^https?:/{2}\w.+$', user_input):
        return LABEL[0]
    elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', user_input):
        return LABEL[1]
    else: 
        return LABEL[2]
        
if __name__ == '__main__':
    # input url
    url = input('Input url: ')
    res = url_judge(url)
    print(res)